use std::{collections::BTreeSet, process::Command};

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
    Vec<u8>,
    Vec<EntryTag>,
);

fn rows() -> Vec<SeedRow> {
    let person = json!({
        "token": "TOKEN-MARKER-1",
        "status": "ok",
        "age": 4242424242u64,
        "did:peer:2.KEY-MARKER-abcdefghijklmnopqrstuvwxyz0123456789": {
            "status": "fine",
            "note": "NOTE-MARKER"
        },
        "list": ["LIST-MARKER"]
    });
    let owner = || EntryTag::Encrypted("owner".into(), "OWNER-MARKER".into());
    vec![
        (
            EntryKind::Item,
            "people",
            "NAME-MARKER-alice",
            person.to_string().into_bytes(),
            vec![
                EntryTag::Plaintext("state".into(), "active".into()),
                EntryTag::Plaintext("phone".into(), "PHONE-MARKER".into()),
                owner(),
            ],
        ),
        (
            EntryKind::Item,
            "people",
            "NAME-MARKER-carol",
            person.to_string().into_bytes(),
            vec![owner()],
        ),
        (
            EntryKind::Item,
            "notes",
            "NAME-MARKER-bob",
            b"RAW-TEXT-MARKER plain".to_vec(),
            vec![],
        ),
        (
            EntryKind::Item,
            "blobs",
            "blob",
            vec![0xff, 0xfe, 1],
            vec![],
        ),
        (
            EntryKind::Kms,
            "keys",
            "signing",
            b"KEY-MATERIAL-MARKER".to_vec(),
            vec![],
        ),
    ]
}

async fn seed(backend: &impl Backend) {
    let mut session = backend.session(None, false).unwrap();
    for (kind, category, name, value, tags) in rows() {
        let value = SecretBytes::from(value);
        session
            .update(
                kind,
                EntryOperation::Insert,
                category,
                name,
                Some(&value),
                Some(&tags),
                None,
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
}

struct Explorer {
    uri: String,
    policy: std::path::PathBuf,
}

impl Explorer {
    fn run(&self, args: &[&str]) -> Output {
        let output = Command::new(env!("CARGO_BIN_EXE_askar-explorer"))
            .env_remove("ASKAR_EXPLORER_URI")
            .env_remove("ASKAR_EXPLORER_PASS_KEY")
            .env_remove("ASKAR_EXPLORER_POLICY")
            .args(args)
            .args(["--uri", &self.uri, "--format", "jsonl"])
            .output()
            .unwrap();
        Output {
            ok: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    fn redacted(&self, args: &[&str]) -> Output {
        let policy = self.policy.to_str().unwrap();
        let mut all = args.to_vec();
        all.extend(["--redact", "--policy", policy]);
        self.run(&all)
    }
}

async fn check(uri: String, directory: &std::path::Path) {
    let policy = directory.join("policy").join("policy.toml");
    std::fs::create_dir_all(policy.parent().unwrap()).unwrap();
    std::fs::write(
        &policy,
        "show_tags = [\"state\"]\nshow_paths = [\"status\"]\n",
    )
    .unwrap();
    let explorer = Explorer { uri, policy };

    // Control: the same commands do show the markers when asked to reveal.
    let revealed = explorer.run(&["ls", "--kind", "any", "--reveal"]).stdout;
    assert!(revealed.contains("NAME-MARKER") && revealed.contains("TOKEN-MARKER"));

    // Collect everything an agent could see.
    let mut seen = String::new();
    let mut record = |output: Output| {
        assert!(output.ok, "{}", output.stderr);
        seen.push_str(&output.stdout);
        seen.push_str(&output.stderr);
        output
    };
    let listing = record(explorer.redacted(&["ls", "--kind", "any", "--limit", "100"]));
    let items = listing.rows();
    assert_eq!(items.len(), 5);
    for item in &items {
        let id = item["id"].to_string();
        record(explorer.redacted(&["get", "--id", &id]));
    }
    // `stats` shows only category names and counts, so it has no redaction mode.
    record(explorer.run(&["stats"]));
    record(explorer.redacted(&["sql", "SELECT * FROM items"]));
    record(explorer.redacted(&[
        "sql",
        "SELECT name, value, ptags, etags, errors, value_bytes FROM items",
    ]));
    record(explorer.redacted(&["sql", "SELECT * FROM items WHERE ptag = 'state=active'"]));
    record(explorer.redacted(&[
        "sql",
        "SELECT json_extract(value, '$.token') AS t, json_extract(value, '$.age') AS a FROM items",
    ]));
    // Searching inside the shapes finds nothing, so it cannot be used to probe values.
    let probe = record(explorer.redacted(&[
        "sql",
        "SELECT count(*) AS n FROM items WHERE value LIKE '%MARKER%' OR name LIKE '%alice%'",
    ]));
    assert_eq!(probe.rows()[0]["n"], 0);

    for secret in ["MARKER", "4242424242", "alice", "carol", "plain"] {
        assert!(!seen.contains(secret), "{secret} leaked:\n{seen}");
    }

    // What agents are meant to see: structure, sizes, allowed paths and tags.
    let find = |name: &str| {
        items
            .iter()
            .find(|item| item["category"] == name)
            .unwrap()
            .clone()
    };
    let people: Vec<&Value> = items
        .iter()
        .filter(|item| item["category"] == "people")
        .collect();
    assert_eq!(people.len(), 2);
    let tags_of = |item: &Value| -> Vec<String> {
        item["tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tag| tag.as_str().unwrap().to_owned())
            .collect()
    };
    let alice = people.iter().find(|item| tags_of(item).len() == 3).unwrap();
    let carol = people.iter().find(|item| tags_of(item).len() == 1).unwrap();
    assert!(tags_of(alice).contains(&"~state=active".to_owned()));
    let pseudonym = |tags: &[String], label: &str| {
        let tag = tags
            .iter()
            .find(|tag| tag.starts_with(label))
            .unwrap()
            .clone();
        tag[label.len()..].to_owned()
    };
    // Equal secret values share a pseudonym; different entry names do not.
    assert_eq!(
        pseudonym(&tags_of(alice), "owner="),
        pseudonym(&tags_of(carol), "owner=")
    );
    assert!(pseudonym(&tags_of(alice), "owner=").starts_with("p-"));
    assert!(pseudonym(&tags_of(alice), "~phone=").starts_with("p-"));
    assert_ne!(alice["name"], carol["name"]);
    assert!(alice["name"].as_str().unwrap().starts_with("p-"));

    let id = alice["id"].to_string();
    let detail = explorer.redacted(&["get", "--id", &id]).rows().remove(0);
    assert_eq!(
        detail["name"], alice["name"],
        "pseudonyms are stable across commands"
    );
    assert_eq!(detail["value"]["status"], "ok", "listed path is shown");
    assert_eq!(detail["value"]["token"], "<string:14>");
    assert_eq!(detail["value"]["age"], "<number>");
    assert_eq!(detail["value"]["list"], json!(["<string:11>"]));
    let opaque = detail["value"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(key, _)| key.starts_with("p-"))
        .expect("the opaque key is pseudonymized");
    assert_eq!(
        opaque.1["status"], "<string:4>",
        "wildcard paths are not allowed by default"
    );

    let note = explorer
        .redacted(&["get", "--id", &find("notes")["id"].to_string()])
        .rows()
        .remove(0);
    assert_eq!(note["value"], "<text:21 chars>");
    let blob = explorer
        .redacted(&["get", "--id", &find("blobs")["id"].to_string()])
        .rows()
        .remove(0);
    assert_eq!(blob["value"], "<binary:3 bytes>");
    let key = explorer
        .redacted(&["get", "--id", &find("keys")["id"].to_string()])
        .rows()
        .remove(0);
    assert_eq!(key["value"], "<key material hidden>");

    // Filters that would let a reader test guesses are refused.
    for args in [
        vec!["ls", "--name", "NAME-MARKER-alice"],
        vec!["ls", "--tag", "owner=OWNER-MARKER"],
        vec!["ls", "--ptag", "phone=PHONE-MARKER"],
        vec!["sql", "SELECT * FROM items WHERE name = 'x'"],
        vec!["sql", "SELECT * FROM items WHERE etag = 'owner=x'"],
        vec!["sql", "SELECT * FROM items WHERE ptag = 'phone=x'"],
    ] {
        let refused = explorer.redacted(&args);
        assert!(!refused.ok, "{args:?} must be refused");
        assert!(!refused.stdout.contains("MARKER"));
    }
    // Filters on a tag the policy lists, and on structure, still work.
    assert_eq!(
        explorer
            .redacted(&["ls", "--ptag", "state=active"])
            .rows()
            .len(),
        1
    );
    assert_eq!(
        explorer
            .redacted(&["ls", "--category", "people"])
            .rows()
            .len(),
        2
    );

    // The pseudonym key is stored next to the policy, privately.
    let key_file = explorer.policy.parent().unwrap().join("pseudonym.key");
    assert!(key_file.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    // Without --redact or --reveal nothing changes: values stay hidden.
    let hidden = explorer.run(&["ls", "--kind", "any"]).stdout;
    assert!(!hidden.contains("TOKEN-MARKER") && !hidden.contains("OWNER-MARKER"));

    let distinct: BTreeSet<String> = items.iter().map(|item| item["name"].to_string()).collect();
    assert_eq!(distinct.len(), 5);
}

#[tokio::test]
async fn sqlite_redacted_view_leaks_nothing() {
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
async fn postgres_redacted_view_leaks_nothing_when_configured() {
    let Ok(base_uri) = std::env::var("POSTGRES_URL") else {
        return;
    };
    let schema = format!("redact_{}", std::process::id());
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
    let cleanup_sql = format!("DROP SCHEMA \"{schema}\" CASCADE");
    sqlx::query(sqlx::AssertSqlSafe(cleanup_sql.as_str()))
        .execute(&mut cleanup)
        .await
        .unwrap();
    checked.unwrap();
}
