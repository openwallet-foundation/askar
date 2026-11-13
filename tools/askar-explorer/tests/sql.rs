use std::process::Command;

use askar_storage::{
    crypto::buffer::SecretBytes,
    entry::{EntryKind, EntryOperation, EntryTag},
    Backend, BackendSession, ManageBackend, PassKey, StoreKeyMethod,
};
use serde_json::{json, Value};
use sqlx::Connection;

const SECRET: &str = "SECRET-VALUE-9f3a";
const KEY_MATERIAL: &str = "PRIVATE-KEY-MATERIAL-77c1";

type SeedRow<'a> = (
    EntryKind,
    &'a str,
    &'a str,
    &'a SecretBytes,
    Vec<EntryTag>,
    Option<i64>,
);

async fn seed(backend: &impl Backend) {
    let mut session = backend.session(None, false).unwrap();
    let secret = SecretBytes::from(format!("{{\"token\":\"{SECRET}\",\"n\":7}}").into_bytes());
    let key = SecretBytes::from(KEY_MATERIAL.as_bytes());
    let rows: [SeedRow<'_>; 4] = [
        (
            EntryKind::Item,
            "records",
            "alpha",
            &secret,
            vec![
                EntryTag::Plaintext("state".into(), "active".into()),
                EntryTag::Encrypted("owner".into(), "alice-private".into()),
            ],
            None,
        ),
        (
            EntryKind::Item,
            "records",
            "beta",
            &secret,
            vec![EntryTag::Plaintext("state".into(), "done".into())],
            None,
        ),
        (
            EntryKind::Item,
            "stale",
            "gamma",
            &secret,
            vec![],
            Some(-1000),
        ),
        (EntryKind::Kms, "keys", "signing", &key, vec![], None),
    ];
    for (kind, category, name, value, tags, expiry) in rows {
        session
            .update(
                kind,
                EntryOperation::Insert,
                category,
                name,
                Some(value),
                Some(&tags),
                expiry,
            )
            .await
            .unwrap();
    }
    session.close(true).await.unwrap();
}

struct Output {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Output {
    fn rows(&self) -> Vec<Value> {
        assert!(self.ok, "{}", self.stderr);
        self.stdout
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn column(&self, name: &str) -> Vec<Value> {
        self.rows()
            .into_iter()
            .map(|row| row[name].clone())
            .collect()
    }
}

fn sql(uri: &str, query: &str, extra: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_askar-explorer"))
        .env_remove("ASKAR_EXPLORER_URI")
        .env_remove("ASKAR_EXPLORER_PASS_KEY")
        .args(["sql", query, "--format", "jsonl", "--uri", uri])
        .args(extra)
        .output()
        .unwrap();
    Output {
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

async fn check(uri: String) {
    let uri = uri.as_str();

    let result = sql(
        uri,
        "SELECT category, count(*) AS n FROM items GROUP BY category ORDER BY category",
        &[],
    );
    assert_eq!(
        result.column("category"),
        [json!("keys"), json!("records"), json!("stale")]
    );
    assert_eq!(result.column("n"), [json!(1), json!(2), json!(1)]);

    // Pushed-down equality conditions, alone and combined.
    let names = |query: &str| sql(uri, query, &[]).column("name");
    assert_eq!(
        names("SELECT name FROM items WHERE category = 'records' ORDER BY name"),
        [json!("alpha"), json!("beta")]
    );
    assert_eq!(
        names("SELECT name FROM items WHERE category = 'records' AND name = 'beta'"),
        [json!("beta")]
    );
    assert_eq!(
        names("SELECT name FROM items WHERE ptag = 'state=active'"),
        [json!("alpha")]
    );
    assert_eq!(
        names(
            "SELECT name FROM items WHERE etag = 'owner=alice-private' AND ptag = 'state=active'"
        ),
        [json!("alpha")]
    );
    assert!(names("SELECT name FROM items WHERE etag = 'owner=nobody'").is_empty());
    assert_eq!(
        names("SELECT name FROM items WHERE kind = 'kms'"),
        [json!("signing")]
    );
    assert_eq!(
        names("SELECT name FROM items WHERE profile = 'main' AND category = 'stale'"),
        [json!("gamma")]
    );
    assert!(names("SELECT name FROM items WHERE profile = 'nope'").is_empty());
    assert!(names("SELECT name FROM items WHERE category = NULL").is_empty());

    // The plan names the columns handed to the database (3 = category, 4 = name, 11 = ptag).
    let plan = |query: &str| {
        let detail = sql(uri, &format!("EXPLAIN QUERY PLAN {query}"), &[]).column("detail");
        detail[0].as_str().unwrap().to_owned()
    };
    assert!(plan("SELECT name FROM items WHERE category = 'records'").ends_with("0:3"));
    assert!(
        plan("SELECT name FROM items WHERE category = 'records' AND name = 'beta'")
            .ends_with("0:3,4")
    );
    assert!(plan("SELECT name FROM items WHERE ptag = 'state=active'").ends_with("0:11"));
    assert!(plan("SELECT name FROM items WHERE name LIKE 'a%'").ends_with("0:"));
    // SQLite may split an OR into two pushed-down lookups; a non-equality test is never pushed down.
    let or_plan = plan("SELECT name FROM items WHERE category = 'a' OR category = 'b'");
    assert!(or_plan.contains("0:3"), "{or_plan}");
    assert!(plan("SELECT name FROM items WHERE value_bytes > 5 OR name LIKE 'a%'").ends_with("0:"));

    // Conditions SQLite cannot push down are still applied correctly.
    assert_eq!(
        names(
            "SELECT name FROM items WHERE category = 'records' OR category = 'stale' ORDER BY name"
        ),
        [json!("alpha"), json!("beta"), json!("gamma")]
    );
    assert_eq!(
        names("SELECT name FROM items WHERE name LIKE 'a%' AND kind = 'item'"),
        [json!("alpha")]
    );
    assert_eq!(
        names("SELECT name FROM items WHERE expiry_mode = 'expired'"),
        [json!("gamma")]
    );
    assert_eq!(
        names("SELECT name FROM items WHERE expiry_mode = 'live' AND kind = 'item' ORDER BY name"),
        [json!("alpha"), json!("beta")]
    );

    // Lookup by id.
    let id = sql(uri, "SELECT id FROM items WHERE name = 'beta'", &[]).column("id")[0].clone();
    assert_eq!(
        names(&format!("SELECT name FROM items WHERE id = {id}")),
        [json!("beta")]
    );

    // Values and tag values stay NULL unless revealed, and key material never appears.
    let hidden = sql(
        uri,
        "SELECT value, ptags, etags FROM items ORDER BY id",
        &[],
    );
    assert!(hidden.ok, "{}", hidden.stderr);
    assert!(!hidden.stdout.contains(SECRET) && !hidden.stdout.contains("alice-private"));
    assert!(hidden.column("value").iter().all(Value::is_null));
    let sizes = sql(
        uri,
        "SELECT value_bytes FROM items WHERE name = 'alpha'",
        &[],
    );
    assert!(sizes.column("value_bytes")[0].as_i64().unwrap() > 0);

    let shown = sql(
        uri,
        "SELECT name, json_extract(value, '$.n') AS n, json_extract(ptags, '$.state') AS state, \
         json_extract(etags, '$.owner') AS owner FROM items WHERE category = 'records' ORDER BY name",
        &["--reveal"],
    );
    assert_eq!(shown.column("n"), [json!(7), json!(7)]);
    assert_eq!(shown.column("state"), [json!("active"), json!("done")]);
    assert_eq!(shown.column("owner"), [json!("alice-private"), Value::Null]);
    let everything = sql(uri, "SELECT * FROM items", &["--reveal"]);
    assert!(everything.stdout.contains(SECRET));
    assert!(
        !everything.stdout.contains(KEY_MATERIAL),
        "key material must stay hidden"
    );

    // The connection is read-only and runs one statement.
    for statement in [
        "CREATE TABLE t(x)",
        "DROP TABLE items",
        "ATTACH DATABASE '/tmp/askar-explorer-attack.db' AS a",
        "PRAGMA writable_schema = 1",
        "SELECT 1; SELECT 2",
    ] {
        let result = sql(uri, statement, &[]);
        assert!(!result.ok, "{statement} must be rejected");
    }
    assert!(!std::path::Path::new("/tmp/askar-explorer-attack.db").exists());

    // Bad arguments produce readable errors.
    let result = sql(uri, "SELECT name FROM items WHERE kind = 'bogus'", &[]);
    assert!(
        !result.ok && result.stderr.contains("kind"),
        "{}",
        result.stderr
    );
    let result = sql(uri, "SELECT name FROM items WHERE ptag = 'novalue'", &[]);
    assert!(
        !result.ok && result.stderr.contains("name=value"),
        "{}",
        result.stderr
    );

    // The row limit cuts the output short and says so.
    let limited = sql(uri, "SELECT name FROM items", &["--limit", "1"]);
    assert_eq!(limited.rows().len(), 1);
    assert!(limited.stderr.contains("--limit"));
}

#[tokio::test]
async fn sqlite_sql_pushdown_hidden_values_and_read_only() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.db");
    let backend = askar_storage::sqlite::SqliteStoreOptions::new(path.to_str().unwrap())
        .unwrap()
        .provision_backend(
            StoreKeyMethod::Unprotected,
            PassKey::empty(),
            Some("main".into()),
            false,
        )
        .await
        .unwrap();
    seed(&backend).await;
    backend.close().await.unwrap();
    check(format!("sqlite://{}", path.display())).await;
}

#[tokio::test]
async fn postgres_sql_when_configured() {
    let Ok(base_uri) = std::env::var("POSTGRES_URL") else {
        return;
    };
    let schema = format!("sql_{}", std::process::id());
    let uri = format!("{base_uri}?schema={schema}");
    let backend = askar_storage::postgres::PostgresStoreOptions::new(uri.as_str())
        .unwrap()
        .provision(
            StoreKeyMethod::Unprotected,
            PassKey::empty(),
            Some("main".into()),
            false,
        )
        .await
        .unwrap();
    seed(&backend).await;
    backend.close().await.unwrap();
    let checked = tokio::spawn({
        let uri = uri.clone();
        async move { check(uri).await }
    })
    .await;
    let mut cleanup = sqlx::PgConnection::connect(&base_uri).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&mut cleanup)
    .await
    .unwrap();
    checked.unwrap();
}

#[tokio::test]
async fn limit_and_profile_filter_avoid_reading_later_profiles() {
    use sqlx::sqlite::SqliteConnectOptions;
    use sqlx::SqliteConnection;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.db");
    let backend = askar_storage::sqlite::SqliteStoreOptions::new(path.to_str().unwrap())
        .unwrap()
        .provision_backend(
            StoreKeyMethod::Unprotected,
            PassKey::empty(),
            Some("main".into()),
            false,
        )
        .await
        .unwrap();
    seed(&backend).await;
    backend.create_profile(Some("broken".into())).await.unwrap();
    backend.close().await.unwrap();
    // A profile whose key cannot be unlocked is only an error when a query reaches it.
    let mut db = SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    sqlx::query("UPDATE profiles SET profile_key = X'00' WHERE name = 'broken'")
        .execute(&mut db)
        .await
        .unwrap();
    db.close().await.unwrap();
    let uri = format!("sqlite://{}", path.display());

    let all = sql(&uri, "SELECT name FROM items", &[]);
    assert!(!all.ok && all.stderr.contains("broken"), "{}", all.stderr);
    assert_eq!(
        sql(&uri, "SELECT name FROM items LIMIT 1", &[])
            .rows()
            .len(),
        1
    );
    assert_eq!(
        sql(&uri, "SELECT name FROM items WHERE profile = 'main'", &[])
            .rows()
            .len(),
        4
    );
}
