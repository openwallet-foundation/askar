use std::process::Command;

use askar_storage::{
    crypto::buffer::SecretBytes,
    entry::{EntryKind, EntryOperation, EntryTag},
    Backend, BackendSession, ManageBackend, PassKey, StoreKeyMethod,
};
use serde_json::Value;
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
    let secret = SecretBytes::from(format!("{{\"token\":\"{SECRET}\"}}").into_bytes());
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

fn run(uri: &str, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_askar-explorer"))
        .env_remove("ASKAR_EXPLORER_URI")
        .env_remove("ASKAR_EXPLORER_PASS_KEY")
        .args(args)
        .args(["--uri", uri])
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn rows(stdout: &str) -> Vec<Value> {
    stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
async fn sqlite_read_commands_filter_page_and_hide_values() {
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
async fn postgres_read_commands_when_configured() {
    let Ok(base_uri) = std::env::var("POSTGRES_URL") else {
        return;
    };
    let schema = format!("read_{}", std::process::id());
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

async fn check(uri: String) {
    let (ok, stdout, stderr) = run(&uri, &["profiles", "--format", "jsonl"]);
    assert!(ok, "{stderr}");
    assert_eq!(rows(&stdout)[0]["profile"], "main");
    assert_eq!(rows(&stdout)[0]["key"], "ok");

    let (ok, stdout, stderr) = run(&uri, &["stats", "--format", "jsonl"]);
    assert!(ok, "{stderr}");
    let stats = rows(&stdout);
    let find = |category: &str| {
        stats
            .iter()
            .find(|row| row["category"] == category)
            .unwrap()
            .clone()
    };
    assert_eq!(find("records")["items"], 2);
    assert_eq!(find("stale")["expired"], 1);
    assert_eq!(find("keys")["kind"], "kms");
    assert!(!stdout.contains(SECRET));

    // Category filtering and paging.
    let (ok, stdout, stderr) = run(
        &uri,
        &[
            "ls",
            "--category",
            "records",
            "--format",
            "jsonl",
            "--limit",
            "1",
        ],
    );
    assert!(ok, "{stderr}");
    let first = rows(&stdout);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0]["name"], "alpha");
    let after = first[0]["id"].to_string();
    let (_, stdout, _) = run(
        &uri,
        &[
            "ls",
            "--category",
            "records",
            "--format",
            "jsonl",
            "--after-id",
            &after,
        ],
    );
    assert_eq!(rows(&stdout)[0]["name"], "beta");

    // Plaintext and encrypted tag filters.
    let (_, stdout, _) = run(&uri, &["ls", "--ptag", "state=active", "--format", "jsonl"]);
    assert_eq!(rows(&stdout).len(), 1);
    let (_, stdout, _) = run(
        &uri,
        &["ls", "--tag", "owner=alice-private", "--format", "jsonl"],
    );
    assert_eq!(rows(&stdout)[0]["name"], "alpha");
    let (_, stdout, _) = run(&uri, &["ls", "--tag", "owner=nobody", "--format", "jsonl"]);
    assert!(rows(&stdout).is_empty());

    // Expiry and kind selection.
    let (_, stdout, _) = run(&uri, &["ls", "--expiry", "expired", "--format", "jsonl"]);
    assert_eq!(rows(&stdout)[0]["name"], "gamma");
    let (_, stdout, _) = run(&uri, &["ls", "--kind", "kms", "--format", "jsonl"]);
    assert_eq!(rows(&stdout)[0]["name"], "signing");

    // Values and tag values stay hidden unless asked for.
    let (_, stdout, _) = run(&uri, &["ls", "--kind", "any"]);
    assert!(!stdout.contains(SECRET) && !stdout.contains("alice-private"));
    assert!(!stdout.contains(KEY_MATERIAL));
    let (_, stdout, _) = run(&uri, &["ls", "--kind", "any", "--reveal"]);
    assert!(stdout.contains(SECRET) && stdout.contains("alice-private"));
    assert!(
        !stdout.contains(KEY_MATERIAL),
        "key material must stay hidden"
    );

    // Table output keeps columns aligned, one line per entry plus the header.
    let (_, stdout, _) = run(&uri, &["ls", "--category", "records"]);
    assert_eq!(stdout.lines().count(), 3);
    assert!(stdout.lines().next().unwrap().starts_with("profile"));

    // One entry by id.
    let id = first[0]["id"].to_string();
    let (ok, stdout, stderr) = run(&uri, &["get", "--id", &id]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("alpha") && !stdout.contains(SECRET));
    let (_, stdout, _) = run(&uri, &["get", "--id", &id, "--reveal"]);
    assert!(stdout.contains(SECRET));
    let (ok, _, stderr) = run(&uri, &["get", "--id", "99999"]);
    assert!(!ok && stderr.contains("No entry"));

    let (ok, _, stderr) = run(&uri, &["ls", "--limit", "0"]);
    assert!(!ok && stderr.contains("limit"));
    let (ok, _, stderr) = run(&uri, &["ls", "--tag", "invalid"]);
    assert!(!ok && stderr.contains("name=value"));
}
