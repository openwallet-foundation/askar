//! The agent API: HTTP access that always applies the redacted view.
//!
//! The view is fixed when the server starts and requests cannot change it. Nothing here
//! writes to the store: agents can only leave *proposals*, which a person reviews and applies
//! with `askar-explorer changes`. Run it where the pass key lives and give agents only the URL
//! and the token; keep the policy, the pseudonym key and the proposals out of anything an
//! agent can read or write.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use askar_storage::inspect::ExpiryFilter;
use axum::{
    extract::{DefaultBodyLimit, Query as UrlQuery, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rand::RngExt;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::{
    changes::{self, ProposalRequest, ProposalStore},
    commands::{self, ListOptions, Table},
    describe::{self, DescribeOptions},
    redact::{Redactor, View},
    source::{Query, Source, TagCondition},
    sql,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_BODY: usize = 64 * 1024;
const MAX_SQL_ROWS: usize = 1000;
const MAX_ENTRIES: i64 = 200;
const MAX_SAMPLE: usize = 5000;

/// Everything the handlers share.
#[derive(Clone)]
pub struct AgentState {
    source: Arc<Mutex<Source>>,
    redactor: Arc<Redactor>,
    token: Arc<String>,
    proposals: Arc<ProposalStore>,
    review_command: Arc<Option<String>>,
}

impl AgentState {
    /// Serve `source` through `redactor`, accepting requests that present `token`, and
    /// keep the proposals that agents make in `proposals`.
    pub fn new(
        source: Source,
        redactor: Redactor,
        token: String,
        proposals: ProposalStore,
    ) -> Self {
        Self {
            source: Arc::new(Mutex::new(source)),
            redactor: Arc::new(redactor),
            token: Arc::new(token),
            proposals: Arc::new(proposals),
            review_command: Arc::new(None),
        }
    }

    /// The command a person runs to review proposals, such as `docker compose exec explorer
    /// askar-explorer`; it is shown to agents so that they can tell the person what to run.
    pub fn with_review_command(mut self, command: Option<String>) -> Self {
        self.review_command = Arc::new(command);
        self
    }

    fn view(&self) -> View {
        View::Redacted(Arc::clone(&self.redactor))
    }
}

struct ApiError(StatusCode, String);

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        Self(StatusCode::BAD_REQUEST, format!("{error:#}"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

type ApiResult = Result<Json<Value>, ApiError>;

fn table_json(table: Table) -> Value {
    json!({ "columns": table.columns, "rows": table.rows })
}

async fn limited<T>(work: impl std::future::Future<Output = Result<T>>) -> Result<T, ApiError> {
    match tokio::time::timeout(REQUEST_TIMEOUT, work).await {
        Ok(result) => Ok(result?),
        Err(_) => Err(ApiError(
            StatusCode::GATEWAY_TIMEOUT,
            "The request took too long; narrow it with a category or a limit".into(),
        )),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

async fn authenticate(State(state): State<AgentState>, request: Request, next: Next) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if presented.is_some_and(|token| constant_time_eq(token.as_bytes(), state.token.as_bytes())) {
        next.run(request).await
    } else {
        ApiError(StatusCode::UNAUTHORIZED, "missing or invalid token".into()).into_response()
    }
}

async fn profiles(State(state): State<AgentState>) -> ApiResult {
    let source = state.source.lock().await;
    Ok(Json(table_json(commands::profiles_table(&source)?)))
}

#[derive(Deserialize)]
struct StatsParams {
    profile: Option<String>,
}

async fn stats(
    State(state): State<AgentState>,
    UrlQuery(params): UrlQuery<StatsParams>,
) -> ApiResult {
    let table = limited(async {
        let mut source = state.source.lock().await;
        commands::stats_table(&mut source, params.profile.as_deref()).await
    })
    .await?;
    Ok(Json(table_json(table)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DescribeRequest {
    category: String,
    profile: Option<String>,
    sample: Option<usize>,
}

async fn describe_category(
    State(state): State<AgentState>,
    Json(request): Json<DescribeRequest>,
) -> ApiResult {
    let options = DescribeOptions {
        profile: request.profile,
        sample: request.sample.unwrap_or(500).min(MAX_SAMPLE),
    };
    let description = limited(async {
        let mut source = state.source.lock().await;
        describe::describe(
            &mut source,
            &request.category,
            &options,
            state.redactor.policy(),
        )
        .await
    })
    .await?;
    Ok(Json(
        json!({ "columns": description.columns, "rows": description.rows }),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryRequest {
    sql: String,
    limit: Option<usize>,
}

async fn query(State(state): State<AgentState>, Json(request): Json<QueryRequest>) -> ApiResult {
    let limit = request.limit.unwrap_or(200).clamp(1, MAX_SQL_ROWS);
    let rows = limited(sql::query(
        Arc::clone(&state.source),
        request.sql,
        state.view(),
        limit,
    ))
    .await?;
    Ok(Json(json!({
        "columns": rows.columns,
        "rows": rows.rows,
        "truncated": rows.truncated,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntriesRequest {
    profile: Option<String>,
    category: Option<String>,
    kind: Option<String>,
    expiry: Option<String>,
    /// Encrypted tags as `name=value`; only tags that the policy lists are accepted.
    #[serde(default)]
    tags: Vec<String>,
    /// Plaintext tags as `name=value`; only tags that the policy lists are accepted.
    #[serde(default)]
    plaintext_tags: Vec<String>,
    limit: Option<i64>,
    after_id: Option<i64>,
}

pub(crate) fn kind_filter(kind: Option<&str>) -> Result<Option<i64>> {
    match kind.unwrap_or("item") {
        "item" => Ok(Some(2)),
        "kms" => Ok(Some(1)),
        "any" => Ok(None),
        other => anyhow::bail!("kind must be item, kms or any, not {other:?}"),
    }
}

pub(crate) fn expiry_filter(expiry: Option<&str>) -> Result<ExpiryFilter> {
    match expiry.unwrap_or("any") {
        "any" => Ok(ExpiryFilter::Any),
        "live" => Ok(ExpiryFilter::LiveOnly),
        "expired" => Ok(ExpiryFilter::ExpiredOnly),
        other => anyhow::bail!("expiry must be any, live or expired, not {other:?}"),
    }
}

async fn entries(
    State(state): State<AgentState>,
    Json(request): Json<EntriesRequest>,
) -> ApiResult {
    let mut tags = Vec::new();
    for spec in &request.tags {
        tags.push(TagCondition::parse(spec, false)?);
    }
    for spec in &request.plaintext_tags {
        tags.push(TagCondition::parse(spec, true)?);
    }
    let options = ListOptions {
        profile: request.profile,
        query: Query {
            id: None,
            kind: kind_filter(request.kind.as_deref())?,
            category: request.category,
            name: None,
            tags,
            expiry: expiry_filter(request.expiry.as_deref())?,
        },
        limit: request.limit.unwrap_or(50).clamp(1, MAX_ENTRIES),
        after_id: request.after_id.unwrap_or(0),
        view: state.view(),
    };
    let table = limited(async {
        let mut source = state.source.lock().await;
        commands::list_table(&mut source, &options).await
    })
    .await?;
    Ok(Json(table_json(table)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryRequest {
    profile: Option<String>,
    id: i64,
}

async fn entry(State(state): State<AgentState>, Json(request): Json<EntryRequest>) -> ApiResult {
    let view = state.view();
    let value = limited(async {
        let mut source = state.source.lock().await;
        let mut selected = source.select_profiles(request.profile.as_deref())?;
        if selected.len() != 1 {
            anyhow::bail!("The store has several profiles; say which one with \"profile\"");
        }
        commands::get_entry(&mut source, &selected.remove(0), request.id, &view).await
    })
    .await?;
    Ok(Json(value))
}

async fn propose(
    State(state): State<AgentState>,
    Json(request): Json<ProposalRequest>,
) -> ApiResult {
    let proposal = limited(async {
        let mut source = state.source.lock().await;
        changes::propose(&mut source, &state.proposals, request).await
    })
    .await?;
    let review = state
        .review_command
        .as_deref()
        .map(|command| format!("{command} changes show {}", proposal.id))
        .unwrap_or_else(|| format!("askar-explorer changes show {}", proposal.id));
    Ok(Json(json!({
        "id": proposal.id,
        "status": proposal.status,
        "title": proposal.title,
        "ops": proposal.ops.len(),
        "review_command": review,
        "note": "Nothing has been changed. A person must review the proposal and apply it.",
    })))
}

async fn list_proposals(State(state): State<AgentState>) -> ApiResult {
    let proposals = state.proposals.list()?;
    Ok(Json(
        json!({ "proposals": proposals.iter().map(|proposal| json!({
        "id": proposal.id,
        "status": proposal.status,
        "title": proposal.title,
        "created_at": proposal.created_at,
        "ops": proposal.ops.len(),
    })).collect::<Vec<_>>() }),
    ))
}

/// The routes and the authentication in front of them.
pub fn router(state: AgentState) -> Router {
    Router::new()
        .route("/v1/profiles", get(profiles))
        .route("/v1/stats", get(stats))
        .route("/v1/describe", post(describe_category))
        .route("/v1/query", post(query))
        .route("/v1/entries", post(entries))
        .route("/v1/entry", post(entry))
        .route("/v1/proposals", get(list_proposals).post(propose))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(state.clone(), authenticate))
        .with_state(state)
}

/// Create a fresh random token and write it where clients can read it.
///
/// The token only unlocks the redacted view, so the file is readable by other local users
/// and containers; keep the directory out of anything that can write policy files.
pub fn create_token_file(path: &Path) -> Result<String> {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    let token = hex::encode(bytes);
    if let Some(directory) = path
        .parent()
        .filter(|directory| !directory.as_os_str().is_empty())
    {
        fs::create_dir_all(directory)?;
    }
    let mut create = OpenOptions::new();
    create.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        create.mode(0o644);
    }
    let mut file = create
        .open(path)
        .with_context(|| format!("Cannot write {}", path.display()))?;
    writeln!(file, "{token}")?;
    Ok(token)
}

/// Open the store, unlock it, and serve the agent API until interrupted.
pub async fn run(
    uri: &str,
    pass_key_env: Option<&str>,
    policy: Option<&Path>,
    listen: SocketAddr,
    token_file: &Path,
    proposals: &Path,
    review_command: Option<String>,
) -> Result<()> {
    let source = Source::open(uri, pass_key_env).await?;
    let redactor = Redactor::open(policy)?;
    let token = create_token_file(token_file)?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("Cannot listen on {listen}"))?;
    println!("Agent API listening on {}", listener.local_addr()?);
    std::io::stdout().flush()?;
    let state = AgentState::new(source, redactor, token, ProposalStore::new(proposals))
        .with_review_command(review_command);
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
