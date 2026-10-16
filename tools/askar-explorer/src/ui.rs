//! The local web interface for people: unlock a store with its pass key, then browse decrypted data.
//!
//! - There is no way in without the pass key (or, for stores that have none, a login code that
//!   is printed only in this process's output). Anything that can reach the port, such as an
//!   agent, can load the login form but has neither. This is the actual boundary.
//! - Repeated failed logins lock logins out for longer each time, up to an hour, so guessing
//!   is slow. (An attacker can also keep the real person locked out; restarting the service
//!   resets this.)
//! - Requests must carry an expected `Host` header, which defeats DNS rebinding from a
//!   browser. A program can forge it, so it is not a defense against other local programs.
//! - The session is one random token in an `HttpOnly`, `SameSite=Strict` cookie. Only one
//!   session exists at a time, and its keys are dropped when it is idle, locked, or replaced.
//! - State changes carry a per-session CSRF token; cross-origin `Origin` headers are refused.
//! - Pages are server-rendered with automatic escaping and no scripts, under a strict
//!   Content-Security-Policy, and are never cached.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use askar_storage::PassKey;
use axum::{
    extract::{DefaultBodyLimit, Form, FromRequestParts, Query as UrlQuery, Request, State},
    http::{header, request::Parts, HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use maud::{html, Markup, PreEscaped, DOCTYPE};
use rand::RngExt;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::{
    agent::{expiry_filter, kind_filter},
    commands::{self, ListOptions, Table},
    redact::View,
    source::{Query, Source, TagCondition},
};

const COOKIE: &str = "askar_session";
const PAGE_SIZE: i64 = 50;
const MAX_FAILURES: u32 = 5;
const MAX_LOCKOUT: Duration = Duration::from_secs(3600);
const MAX_FORM: usize = 16 * 1024;
const WORK_TIMEOUT: Duration = Duration::from_secs(60);

const STYLE: &str = "
body{font:15px/1.45 system-ui,sans-serif;margin:0;color:#1b1f24;background:#f6f8fa}
nav{display:flex;gap:1rem;align-items:center;padding:.6rem 1.2rem;background:#24292f}
nav a,nav button{color:#fff;text-decoration:none;background:none;border:0;font:inherit;cursor:pointer}
nav form{margin:0 0 0 auto}
main{padding:1rem 1.2rem;max-width:1200px}
h1{font-size:1.3rem;margin:.2rem 0 1rem}
table{border-collapse:collapse;background:#fff;width:100%}
th,td{border:1px solid #d0d7de;padding:.3rem .5rem;text-align:left;vertical-align:top}
th{background:#eaeef2}
td.num{text-align:right}
code,pre{font:13px ui-monospace,monospace}
pre{background:#fff;border:1px solid #d0d7de;padding:.7rem;overflow:auto;white-space:pre-wrap;word-break:break-word}
form.filters{display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem;align-items:end}
form.filters label{display:flex;flex-direction:column;font-size:.8rem}
.warn{background:#fff8c5;border:1px solid #d4a72c;padding:.5rem .7rem;margin:.5rem 0}
.muted{color:#656d76}
";

/// Settings for [`run`].
#[derive(Clone, Debug)]
pub struct Options {
    /// Where to listen.
    pub listen: SocketAddr,
    /// `Host` header values to accept; when empty, `localhost` and `127.0.0.1` on the bound port.
    pub allowed_hosts: Vec<String>,
    /// How long a session may sit unused before its keys are dropped.
    pub idle_timeout: Duration,
    /// How long logins are refused after too many failures.
    pub login_lockout: Duration,
}

struct Session {
    token: String,
    csrf: String,
    source: Arc<Mutex<Source>>,
    last_seen: Instant,
}

#[derive(Default)]
struct Attempts {
    failures: u32,
    /// How many times logins have been locked out since the last successful one.
    lockouts: u32,
    blocked_until: Option<Instant>,
}

struct Inner {
    uri: String,
    /// For stores without a pass key: the code that stands in for it.
    login_code: Option<String>,
    login_csrf: String,
    allowed_hosts: Vec<String>,
    idle_timeout: Duration,
    login_lockout: Duration,
    session: StdMutex<Option<Session>>,
    attempts: StdMutex<Attempts>,
}

/// Everything the handlers share.
#[derive(Clone)]
pub struct UiState(Arc<Inner>);

fn random_hex() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
}

/// Percent-encode a query value.
fn enc(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

impl UiState {
    fn authorize(&self, token: &str) -> Option<(Arc<Mutex<Source>>, String)> {
        let mut guard = self.0.session.lock().unwrap_or_else(|e| e.into_inner());
        let session = guard.as_mut()?;
        if session.last_seen.elapsed() >= self.0.idle_timeout {
            *guard = None;
            return None;
        }
        if !constant_time_eq(token.as_bytes(), session.token.as_bytes()) {
            return None;
        }
        session.last_seen = Instant::now();
        Some((Arc::clone(&session.source), session.csrf.clone()))
    }

    /// Drop the session if it has been idle too long, so its keys do not linger.
    fn expire(&self) {
        let mut guard = self.0.session.lock().unwrap_or_else(|e| e.into_inner());
        if guard
            .as_ref()
            .is_some_and(|session| session.last_seen.elapsed() >= self.0.idle_timeout)
        {
            *guard = None;
        }
    }

    fn lock_out(&self) -> Option<Duration> {
        let attempts = self.0.attempts.lock().unwrap_or_else(|e| e.into_inner());
        attempts
            .blocked_until
            .and_then(|until| until.checked_duration_since(Instant::now()))
    }

    fn record_failure(&self) {
        let mut attempts = self.0.attempts.lock().unwrap_or_else(|e| e.into_inner());
        attempts.failures += 1;
        if attempts.failures >= MAX_FAILURES {
            attempts.failures = 0;
            attempts.lockouts = attempts.lockouts.saturating_add(1);
            let wait = self
                .0
                .login_lockout
                .saturating_mul(1u32 << (attempts.lockouts - 1).min(20))
                .min(MAX_LOCKOUT);
            attempts.blocked_until = Some(Instant::now() + wait);
        }
    }

    fn record_success(&self) {
        let mut attempts = self.0.attempts.lock().unwrap_or_else(|e| e.into_inner());
        *attempts = Attempts::default();
    }
}

/// A request from the signed-in person.
struct Authed {
    source: Arc<Mutex<Source>>,
    csrf: String,
}

impl FromRequestParts<UiState> for Authed {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &UiState,
    ) -> std::result::Result<Self, Response> {
        cookie(&parts.headers, COOKIE)
            .and_then(|token| state.authorize(&token))
            .map(|(source, csrf)| Self { source, csrf })
            .ok_or_else(|| Redirect::to("/").into_response())
    }
}

struct PageError(StatusCode, String);

impl From<anyhow::Error> for PageError {
    fn from(error: anyhow::Error) -> Self {
        Self(StatusCode::BAD_REQUEST, format!("{error:#}"))
    }
}

impl IntoResponse for PageError {
    fn into_response(self) -> Response {
        let body = html! { p class="warn" { (self.1) } p { a href="/" { "Back" } } };
        (self.0, layout("Something went wrong", None, body)).into_response()
    }
}

type Page = std::result::Result<Response, PageError>;

async fn limited<T>(work: impl std::future::Future<Output = Result<T>>) -> Result<T, PageError> {
    match tokio::time::timeout(WORK_TIMEOUT, work).await {
        Ok(result) => Ok(result?),
        Err(_) => Err(PageError(
            StatusCode::GATEWAY_TIMEOUT,
            "That took too long; narrow it with a category".into(),
        )),
    }
}

fn layout(title: &str, csrf: Option<&str>, body: Markup) -> Html<String> {
    Html(
        html! {
            (DOCTYPE)
            html lang="en" {
                head {
                    meta charset="utf-8";
                    title { (title) " - Askar explorer" }
                    style { (PreEscaped(STYLE)) }
                }
                body {
                    @if let Some(csrf) = csrf {
                        nav {
                            a href="/" { "Dashboard" }
                            a href="/entries" { "Entries" }
                            form method="post" action="/logout" {
                                input type="hidden" name="csrf" value=(csrf);
                                button type="submit" { "Lock" }
                            }
                        }
                    }
                    main { h1 { (title) } (body) }
                }
            }
        }
        .into_string(),
    )
}

fn page(title: &str, csrf: &str, body: Markup) -> Response {
    layout(title, Some(csrf), body).into_response()
}

/// Refuse unexpected hosts and cross-origin posts, and add the security headers to everything.
async fn guard(State(state): State<UiState>, request: Request, next: Next) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let allowed = state
        .0
        .allowed_hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&host));
    let login_with_opaque_origin = request.uri().path() == "/login"
        && request
            .headers()
            .get(header::ORIGIN)
            .is_some_and(|origin| origin.as_bytes() == b"null");
    let cross_origin = request.method() != axum::http::Method::GET
        && !login_with_opaque_origin
        && request
            .headers()
            .get(header::ORIGIN)
            .is_some_and(|origin| origin.as_bytes() != format!("http://{host}").as_bytes());
    let mut response = if !allowed {
        (StatusCode::MISDIRECTED_REQUEST, "Unexpected host").into_response()
    } else if cross_origin {
        (StatusCode::FORBIDDEN, "Cross-origin request refused").into_response()
    } else {
        next.run(request).await
    };
    let headers = response.headers_mut();
    for (name, value) in [
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; \
             frame-ancestors 'none'; base-uri 'none'",
        ),
        (header::CACHE_CONTROL, "no-store"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (
            HeaderName::from_static("cross-origin-resource-policy"),
            "same-origin",
        ),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

fn login_page(state: &UiState, message: Option<&str>) -> Html<String> {
    let label = if state.0.login_code.is_some() {
        "Login code (printed in this service's log)"
    } else {
        "Store pass key"
    };
    layout(
        "Unlock the store",
        None,
        html! {
            @if let Some(message) = message { p class="warn" { (message) } }
            form method="post" action="/login" {
                input type="hidden" name="login_csrf" value=(state.0.login_csrf);
                label { (label) " " input type="password" name="secret" autocomplete="off" autofocus required; }
                " "
                button type="submit" { "Unlock" }
            }
            p class="muted" { "Sessions end after a period of inactivity; the keys are then dropped from memory." }
        },
    )
}

async fn home(State(state): State<UiState>, headers: HeaderMap) -> Page {
    let authed = cookie(&headers, COOKIE).and_then(|token| state.authorize(&token));
    let Some((source, csrf)) = authed else {
        return Ok(login_page(&state, None).into_response());
    };
    let mut source = source.lock().await;
    let profiles = commands::profiles_table(&source)?;
    let stats = limited(commands::stats_table(&mut source, None)).await?;
    let body = html! {
        h2 { "Profiles" }
        table {
            thead { tr { th { "Profile" } th { "Key" } } }
            tbody {
                @for row in &profiles.rows {
                    tr { td { (text(&row[1])) } td { (text(&row[2])) } }
                }
            }
        }
        h2 { "Categories" }
        table {
            thead { tr { th { "Profile" } th { "Kind" } th { "Category" } th { "Entries" } th { "Expired" } th { "Encrypted bytes" } } }
            tbody {
                @for row in &stats.rows {
                    tr {
                        td { (text(&row[0])) }
                        td { (text(&row[1])) }
                        td {
                            a href=(format!("/entries?profile={}&category={}&kind={}",
                                enc(&text(&row[0])), enc(&text(&row[2])),
                                if row[1] == "kms" { "kms" } else { "item" })) { (text(&row[2])) }
                        }
                        td class="num" { (text(&row[3])) }
                        td class="num" { (text(&row[4])) }
                        td class="num" { (text(&row[5])) }
                    }
                }
            }
        }
    };
    Ok(page("Dashboard", &csrf, body))
}

#[derive(Deserialize)]
struct LoginForm {
    secret: String,
    login_csrf: String,
}

async fn login(State(state): State<UiState>, Form(form): Form<LoginForm>) -> Response {
    if !constant_time_eq(form.login_csrf.as_bytes(), state.0.login_csrf.as_bytes()) {
        return (StatusCode::FORBIDDEN, "Missing or invalid login form token").into_response();
    }
    if let Some(wait) = state.lock_out() {
        let message = format!(
            "Too many failed attempts. Try again in {}s.",
            wait.as_secs() + 1
        );
        return (
            StatusCode::TOO_MANY_REQUESTS,
            login_page(&state, Some(&message)),
        )
            .into_response();
    }
    let code_ok = state
        .0
        .login_code
        .as_ref()
        .is_none_or(|code| constant_time_eq(code.as_bytes(), form.secret.as_bytes()));
    // A wrong pass key does not always fail to open: profiles may just stay locked. Either way,
    // and for a wrong login code, it counts as a failed attempt.
    let source = if code_ok {
        let has_code = state.0.login_code.is_some();
        let secret = form.secret;
        match Source::open_with(&state.0.uri, move |key_reference| {
            Ok(if key_reference == "none" || has_code {
                PassKey::empty()
            } else {
                PassKey::from(secret)
            })
        })
        .await
        {
            Ok(source) => Some(source).filter(|source| {
                source
                    .select_profiles(None)
                    .is_ok_and(|profiles| profiles.iter().any(|p| p.key_error().is_none()))
            }),
            Err(error) => {
                eprintln!("Login could not open the store: {error:#}");
                None
            }
        }
    } else {
        None
    };
    let Some(source) = source else {
        state.record_failure();
        return (
            StatusCode::UNAUTHORIZED,
            login_page(
                &state,
                Some("That did not unlock the store, or the store could not be opened."),
            ),
        )
            .into_response();
    };
    let token = random_hex();
    let session = Session {
        token: token.clone(),
        csrf: random_hex(),
        source: Arc::new(Mutex::new(source)),
        last_seen: Instant::now(),
    };
    *state.0.session.lock().unwrap_or_else(|e| e.into_inner()) = Some(session);
    state.record_success();
    let mut response = Redirect::to("/").into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/"
        ))
        .expect("a hex token is a valid header value"),
    );
    response
}

#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
}

async fn logout(
    State(state): State<UiState>,
    authed: Authed,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !constant_time_eq(form.csrf.as_bytes(), authed.csrf.as_bytes()) {
        return (StatusCode::FORBIDDEN, "Missing or invalid form token").into_response();
    }
    drop(authed);
    *state.0.session.lock().unwrap_or_else(|e| e.into_inner()) = None;
    let mut response = Redirect::to("/").into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("askar_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
    );
    response
}

fn text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn short(value: &Value) -> String {
    let full = match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    if full.chars().count() > 80 {
        let kept: String = full.chars().take(80).collect();
        format!("{kept}...")
    } else {
        full
    }
}

fn pretty_value(value: &Value) -> String {
    match value {
        Value::String(text) => serde_json::from_str::<Value>(text)
            .and_then(|parsed| serde_json::to_string_pretty(&parsed))
            .unwrap_or_else(|_| text.clone()),
        other => serde_json::to_string_pretty(other).unwrap_or_default(),
    }
}

fn field<'a>(table: &Table, row: &'a [Value], name: &str) -> &'a Value {
    static NULL: Value = Value::Null;
    table
        .columns
        .iter()
        .position(|column| column == name)
        .and_then(|index| row.get(index))
        .unwrap_or(&NULL)
}

fn present(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.is_empty())
}

#[derive(Deserialize, Default)]
struct EntriesParams {
    profile: Option<String>,
    category: Option<String>,
    name: Option<String>,
    tag: Option<String>,
    ptag: Option<String>,
    kind: Option<String>,
    expiry: Option<String>,
    after: Option<i64>,
}

async fn entries(authed: Authed, UrlQuery(params): UrlQuery<EntriesParams>) -> Page {
    let mut source = authed.source.lock().await;
    let profiles = source.select_profiles(None)?;
    let profile = present(params.profile.clone()).unwrap_or_else(|| profiles[0].name.clone());
    let category = present(params.category.clone());
    let name = present(params.name.clone());
    let tag = present(params.tag.clone());
    let ptag = present(params.ptag.clone());
    let kind = present(params.kind.clone());
    let expiry = present(params.expiry.clone());
    let mut tags = Vec::new();
    if let Some(spec) = &tag {
        tags.push(TagCondition::parse(spec, false)?);
    }
    if let Some(spec) = &ptag {
        tags.push(TagCondition::parse(spec, true)?);
    }
    let options = ListOptions {
        profile: Some(profile.clone()),
        query: Query {
            id: None,
            kind: kind_filter(kind.as_deref())?,
            category: category.clone(),
            name: name.clone(),
            tags,
            expiry: expiry_filter(expiry.as_deref())?,
        },
        limit: PAGE_SIZE + 1,
        after_id: params.after.unwrap_or(0).max(0),
        view: View::Reveal,
    };
    let table = limited(commands::list_table(&mut source, &options)).await?;
    let more = table.rows.len() as i64 > PAGE_SIZE;
    let rows: Vec<&Vec<Value>> = table.rows.iter().take(PAGE_SIZE as usize).collect();
    let next = rows
        .last()
        .filter(|_| more)
        .and_then(|row| field(&table, row, "id").as_i64());
    let kind_text = kind.clone().unwrap_or_else(|| "item".into());
    let expiry_text = expiry.clone().unwrap_or_else(|| "any".into());
    let mut next_link = format!(
        "/entries?profile={}&kind={}&expiry={}",
        enc(&profile),
        enc(&kind_text),
        enc(&expiry_text)
    );
    for (key, value) in [
        ("category", &category),
        ("name", &name),
        ("tag", &tag),
        ("ptag", &ptag),
    ] {
        if let Some(value) = value {
            next_link.push_str(&format!("&{key}={}", enc(value)));
        }
    }
    let body = html! {
        form class="filters" method="get" action="/entries" {
            label { "Profile"
                select name="profile" {
                    @for item in &profiles {
                        option value=(item.name) selected[item.name == profile] { (item.name) }
                    }
                }
            }
            label { "Category" input name="category" value=(category.clone().unwrap_or_default()); }
            label { "Name (exact)" input name="name" value=(name.clone().unwrap_or_default()); }
            label { "Encrypted tag (name=value)" input name="tag" value=(tag.clone().unwrap_or_default()); }
            label { "Plaintext tag (name=value)" input name="ptag" value=(ptag.clone().unwrap_or_default()); }
            label { "Kind"
                select name="kind" {
                    @for option in ["item", "kms", "any"] {
                        option value=(option) selected[option == kind_text] { (option) }
                    }
                }
            }
            label { "Expiry"
                select name="expiry" {
                    @for option in ["any", "live", "expired"] {
                        option value=(option) selected[option == expiry_text] { (option) }
                    }
                }
            }
            button type="submit" { "Filter" }
        }
        table {
            thead { tr { th { "Id" } th { "Category" } th { "Name" } th { "Bytes" } th { "Expiry" } th { "Tags" } th { "Value" } th { "Problems" } } }
            tbody {
                @for row in &rows {
                    @let id = field(&table, row, "id");
                    tr {
                        td { a href=(format!("/entry?profile={}&id={}", enc(&profile), text(id))) { (text(id)) } }
                        td { (text(field(&table, row, "category"))) }
                        td { (short(field(&table, row, "name"))) }
                        td class="num" { (text(field(&table, row, "value_bytes"))) }
                        td { (text(field(&table, row, "expiry"))) }
                        td { (field(&table, row, "tags").as_array().map(|tags| tags.iter().map(text).collect::<Vec<_>>().join(", ")).unwrap_or_default()) }
                        td {
                            details {
                                summary { code { (short(field(&table, row, "value"))) } }
                                pre { (pretty_value(field(&table, row, "value"))) }
                            }
                        }
                        td { (field(&table, row, "errors").as_array().map(|errors| errors.iter().map(text).collect::<Vec<_>>().join("; ")).unwrap_or_default()) }
                    }
                }
            }
        }
        @if rows.is_empty() { p class="muted" { "No entries match." } }
        @if let Some(next) = next {
            p { a href=(format!("{next_link}&after={next}")) { "Next page" } }
        }
    };
    Ok(page("Entries", &authed.csrf, body))
}

#[derive(Deserialize)]
struct EntryParams {
    profile: String,
    id: i64,
}

async fn entry(authed: Authed, UrlQuery(params): UrlQuery<EntryParams>) -> Page {
    let mut source = authed.source.lock().await;
    let mut selected = source.select_profiles(Some(&params.profile))?;
    let value = limited(commands::get_entry(
        &mut source,
        &selected.remove(0),
        params.id,
        &View::Reveal,
    ))
    .await?;
    let shown = pretty_value(&value["value"]);
    let body = html! {
        table {
            @for name in ["profile", "id", "kind", "category", "name", "expiry"] {
                tr { th { (name) } td { (text(&value[name])) } }
            }
        }
        @for error in value["errors"].as_array().into_iter().flatten() {
            p class="warn" { (text(error)) }
        }
        h2 { "Tags" }
        @if value["tags"].as_array().is_none_or(|tags| tags.is_empty()) {
            p class="muted" { "No tags." }
        } @else {
            ul { @for tag in value["tags"].as_array().into_iter().flatten() { li { code { (text(tag)) } } } }
        }
        h2 { "Value" }
        pre { (shown) }
        p { a href=(format!("/entries?profile={}", enc(&params.profile))) { "Back to entries" } }
    };
    Ok(page(&format!("Entry {}", params.id), &authed.csrf, body))
}

/// The routes and the guards in front of them.
pub fn router(state: UiState) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/entries", get(entries))
        .route("/entry", get(entry))
        .layer(DefaultBodyLimit::max(MAX_FORM))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// Serve the web interface until interrupted.
pub async fn run(uri: &str, options: Options) -> Result<()> {
    let (key_reference, _) = crate::apply::source_fingerprint(uri)
        .await
        .context("Cannot read the store")?;
    let login_code = (key_reference == "none").then(|| {
        let mut bytes = [0u8; 8];
        rand::rng().fill(&mut bytes);
        hex::encode(bytes)
    });
    let listener = tokio::net::TcpListener::bind(options.listen)
        .await
        .with_context(|| format!("Cannot listen on {}", options.listen))?;
    let address = listener.local_addr()?;
    let allowed_hosts = if options.allowed_hosts.is_empty() {
        vec![
            format!("localhost:{}", address.port()),
            format!("127.0.0.1:{}", address.port()),
        ]
    } else {
        options.allowed_hosts
    };
    let state = UiState(Arc::new(Inner {
        uri: uri.to_owned(),
        login_code: login_code.clone(),
        login_csrf: random_hex(),
        allowed_hosts,
        idle_timeout: options.idle_timeout,
        login_lockout: options.login_lockout,
        session: StdMutex::new(None),
        attempts: StdMutex::new(Attempts::default()),
    }));
    println!("Web UI listening on http://{address}");
    if let Some(code) = login_code {
        println!("Login code: {code}");
    }
    std::io::Write::flush(&mut std::io::stdout())?;
    let sweeper = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            sweeper.expire();
        }
    });
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
