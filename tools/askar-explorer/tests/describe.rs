use std::process::Command;

use askar_storage::{
    crypto::buffer::SecretBytes,
    entry::{EntryKind, EntryOperation, EntryTag},
    Backend, BackendSession, ManageBackend, PassKey, StoreKeyMethod,
};
use serde_json::{json, Value};
use sqlx::Connection;

type SeedRow = (
    EntryKind,
    &'static str,
    &'static str,
    String,
    Vec<EntryTag>,
    Option<i64>,
);

fn rows() -> Vec<SeedRow> {
    let did = "did:peer:2.KEY-MARKER-abcdefghijklmnopqrstuvwxyz0123456789";
    let first = json!({
        "status": "ok", "age": 1, "token": "TOKEN-A", "flags": {"admin": true},
        "list": ["x", "y"], did: {"status": "s"}
    });
    let tags = |state: &str| {
        vec![
            EntryTag::Plaintext("state".into(), state.into()),
            EntryTag::Encrypted("owner".into(), "OWNER-MARKER".into()),
        ]
    };
    vec![
        (
            EntryKind::Item,
            "people",
            "p1",
            first.to_string(),
            tags("active"),
            None,
        ),
        (
            EntryKind::Item,
            "people",
            "p2",
            json!({"status": "ok", "age": 2, "token": "TOKEN-B", "list": []}).to_string(),
            tags("active"),
            None,
        ),
        (
            EntryKind::Item,
            "people",
            "p3",
            json!({"status": "bad", "token": "TOKEN-C", "extra": null}).to_string(),
            vec![],
            None,
        ),
        (
            EntryKind::Item,
            "people",
            "p4",
            "hello-TEXT-MARKER".into(),
            vec![],
            None,
        ),
        (
            EntryKind::Item,
            "people",
            "p5",
            json!({"status": "ok"}).to_string(),
            tags("done"),
            Some(-1000),
        ),
        (
            EntryKind::Item,
            "other",
            "o1",
            json!({"status": "no"}).to_string(),
            vec![],
            None,
        ),
        (
            EntryKind::Kms,
            "keys",
            "k1",
            "KEY-MATERIAL-MARKER".into(),
            vec![],
            None,
        ),
    ]
}

async fn seed(backend: &impl Backend) {
    let mut session = backend.session(None, false).unwrap();
    for (kind, category, name, value, tags, expiry) in rows() {
        let value = SecretBytes::from(value.into_bytes());
        session
            .update(
                kind,
                EntryOperation::Insert,
                category,
                name,
                Some(&value),
                Some(&tags),
                expiry,
            )
            .await
            .unwrap();
    }
    session.close(true).await.unwrap();
}

struct Described {
    stdout: String,
    rows: Vec<Value>,
}

impl Described {
    fn get(&self, section: &str, name: &str) -> &Value {
        self.rows
            .iter()
            .find(|row| row["section"] == section && row["name"] == name)
            .unwrap_or_else(|| panic!("no {section} {name} in\n{}", self.stdout))
    }
}

fn describe(uri: &str, args: &[&str]) -> (bool, Described, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_askar-explorer"))
        .env_remove("ASKAR_EXPLORER_URI")
        .env_remove("ASKAR_EXPLORER_PASS_KEY")
        .env_remove("ASKAR_EXPLORER_POLICY")
        .args(["describe"])
        .args(args)
        .args(["--format", "jsonl", "--uri", uri])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let rows = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (
        output.status.success(),
        Described { stdout, rows },
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

async fn check(uri: String, directory: &std::path::Path) {
    let policy = directory.join("policy.toml");
    std::fs::write(
        &policy,
        "show_tags = [\"state\"]\nshow_paths = [\"status\"]\n",
    )
    .unwrap();
    let policy = policy.to_str().unwrap();

    let (ok, shown, stderr) = describe(&uri, &["people", "--policy", policy]);
    assert!(ok, "{stderr}");

    // Counts come from the store, not the sample.
    assert_eq!(shown.get("summary", "entries")["count"], 5);
    assert_eq!(shown.get("summary", "expired")["count"], 1);
    assert_eq!(shown.get("summary", "sampled")["count"], 5);
    assert_eq!(shown.get("summary", "json_documents")["count"], 4);
    assert_eq!(shown.get("summary", "text_values")["count"], 1);
    assert_eq!(shown.get("summary", "with_expiry")["count"], 1);
    assert!(
        shown.get("summary", "value_bytes_min")["count"]
            .as_i64()
            .unwrap()
            > 0
    );

    // Fields: presence, types, distinct counts and lengths.
    let status = shown.get("field", "status");
    assert_eq!(status["types"], "string");
    assert_eq!(status["count"], 4);
    assert_eq!(status["present_pct"], 100.0);
    assert_eq!(status["distinct"], 2);
    assert_eq!(
        status["values"],
        json!(["ok (3)", "bad (1)"]),
        "listed path shows values"
    );
    let age = shown.get("field", "age");
    assert_eq!(
        (age["types"].clone(), age["present_pct"].clone()),
        (json!("number"), json!(50.0))
    );
    assert_eq!(shown.get("field", "$")["types"], "object");
    assert_eq!(shown.get("field", "flags")["types"], "object");
    assert_eq!(
        shown.get("field", "flags.admin")["values"],
        json!(["true (1)"])
    );
    assert_eq!(shown.get("field", "extra")["types"], "null");
    let list = shown.get("field", "list");
    assert_eq!(
        (list["types"].clone(), list["length"].clone()),
        (json!("array"), json!("0-2"))
    );
    assert_eq!(shown.get("field", "list[]")["count"], 2);
    let token = shown.get("field", "token");
    assert_eq!(token["distinct"], 3);
    assert_eq!(token["length"], "7-7");
    assert_eq!(token["values"], json!([]), "unlisted paths show no values");
    // Identifier-like keys are grouped under a wildcard instead of being named.
    let wildcard = shown.get("field", "*.status");
    assert_eq!(wildcard["values"], json!([]));
    assert_eq!(wildcard["present_pct"], 25.0);

    // Tags.
    let state = shown.get("tag", "~state");
    assert_eq!(state["types"], "plaintext");
    assert_eq!(state["count"], 3);
    assert_eq!(state["distinct"], 2);
    assert_eq!(
        state["values"],
        json!(["active (2)", "done (1)"]),
        "listed tag shows values"
    );
    let owner = shown.get("tag", "owner");
    assert_eq!(owner["types"], "encrypted");
    assert_eq!(owner["distinct"], 1);
    assert_eq!(owner["values"], json!([]), "unlisted tag shows no values");

    // Nothing sensitive is in the output, and other categories are not mixed in.
    for secret in [
        "TOKEN-",
        "OWNER-MARKER",
        "did:peer",
        "KEY-MARKER",
        "TEXT-MARKER",
        "KEY-MATERIAL",
    ] {
        assert!(
            !shown.stdout.contains(secret),
            "{secret} leaked:\n{}",
            shown.stdout
        );
    }
    assert!(shown.rows.iter().all(|row| row["name"] != "keys"));

    // Without a policy no real value is shown, except booleans.
    let (ok, bare, stderr) = describe(&uri, &["people", "--policy", "/nonexistent/policy.toml"]);
    assert!(ok, "{stderr}");
    for row in bare.rows.iter().filter(|row| row["section"] != "summary") {
        let values = row["values"].as_array().unwrap();
        assert!(values.is_empty() || row["name"] == "flags.admin", "{row}");
    }

    // The sample cap and unknown categories.
    let (_, small, _) = describe(&uri, &["people", "--sample", "2", "--policy", policy]);
    assert_eq!(small.get("summary", "sampled")["count"], 2);
    assert_eq!(small.get("summary", "entries")["count"], 5);
    let (ok, empty, _) = describe(&uri, &["nothing", "--policy", policy]);
    assert!(ok);
    assert_eq!(empty.get("summary", "entries")["count"], 0);
    assert_eq!(empty.get("summary", "sampled")["count"], 0);
    assert!(empty.rows.iter().all(|row| row["section"] == "summary"));

    // A mistyped policy is an error rather than a silent default.
    let broken = std::path::Path::new(policy).with_file_name("broken.toml");
    std::fs::write(&broken, "show_path = [\"x\"]").unwrap();
    let (ok, _, stderr) = describe(&uri, &["people", "--policy", broken.to_str().unwrap()]);
    assert!(!ok && stderr.contains("policy"), "{stderr}");
}

#[tokio::test]
async fn sqlite_describe_summarizes_structure_without_leaking() {
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
    check(format!("sqlite://{}", path.display()), directory.path()).await;
}

#[tokio::test]
async fn postgres_describe_when_configured() {
    let Ok(base_uri) = std::env::var("POSTGRES_URL") else {
        return;
    };
    let schema = format!("describe_{}", std::process::id());
    let uri = format!("{base_uri}?schema={schema}");
    let directory = tempfile::tempdir().unwrap();
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
        let (uri, path) = (uri.clone(), directory.path().to_owned());
        async move { check(uri, &path).await }
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
