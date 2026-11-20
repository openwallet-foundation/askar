use askar_explorer::{
    changes::{self, ApplyOptions, Op, ProposalRequest, ProposalStore, Status},
    source::{Query, Source},
};
use askar_storage::{
    crypto::buffer::SecretBytes,
    entry::{EntryKind, EntryOperation, EntryTag},
    Backend, BackendSession, ManageBackend, PassKey, StoreKeyMethod,
};
use serde_json::json;
use sqlx::Connection;

type SeedRow<'a> = (
    EntryKind,
    &'a str,
    &'a str,
    String,
    Vec<EntryTag>,
    Option<i64>,
);

async fn seed(backend: &impl Backend) {
    let mut session = backend.session(None, false).unwrap();
    let rows: Vec<SeedRow<'_>> = vec![
        (
            EntryKind::Item,
            "people",
            "alice",
            json!({"state": "active", "note": "OLD-SECRET-alice", "n": 1}).to_string(),
            vec![
                EntryTag::Plaintext("state".into(), "active".into()),
                EntryTag::Encrypted("owner".into(), "OWNER-X".into()),
            ],
            None,
        ),
        (
            EntryKind::Item,
            "people",
            "bob",
            json!({"state": "active", "note": "OLD-SECRET-bob"}).to_string(),
            vec![],
            None,
        ),
        (
            EntryKind::Item,
            "people",
            "carol",
            json!({"state": "gone"}).to_string(),
            vec![],
            Some(-1000),
        ),
        (
            EntryKind::Kms,
            "keys",
            "k",
            "KEY-MATERIAL".into(),
            vec![],
            None,
        ),
    ];
    for (kind, category, name, value, tags, expiry) in rows {
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

async fn id_of(uri: &str, name: &str) -> i64 {
    let mut source = Source::open(uri, None).await.unwrap();
    let profile = source.select_profiles(None).unwrap().remove(0);
    let items = source
        .scan(&profile, &Query::default(), 0, 100)
        .await
        .unwrap();
    items
        .into_iter()
        .find(|item| item.name.as_deref().ok() == Some(name))
        .unwrap_or_else(|| panic!("no entry {name}"))
        .id
}

async fn value_of(uri: &str, name: &str) -> Option<serde_json::Value> {
    let mut source = Source::open(uri, None).await.unwrap();
    let profile = source.select_profiles(None).unwrap().remove(0);
    let items = source
        .scan(&profile, &Query::default(), 0, 100)
        .await
        .unwrap();
    items
        .into_iter()
        .find(|item| item.name.as_deref().ok() == Some(name))
        .map(|item| serde_json::from_slice(item.value.unwrap().as_ref()).unwrap())
}

fn request(ops: serde_json::Value) -> ProposalRequest {
    serde_json::from_value(
        json!({"title": "Fix states", "rationale": "They are stuck", "ops": ops}),
    )
    .unwrap()
}

async fn propose(
    uri: &str,
    store: &ProposalStore,
    ops: serde_json::Value,
) -> anyhow::Result<String> {
    let mut source = Source::open(uri, None).await?;
    Ok(changes::propose(&mut source, store, request(ops)).await?.id)
}

async fn apply(
    store: &ProposalStore,
    id: &str,
    read: &str,
    write: Option<&str>,
    commit: bool,
    backup: bool,
    answer: bool,
) -> (anyhow::Result<bool>, String, Vec<String>) {
    let options = ApplyOptions {
        read_uri: read,
        write_uri: write,
        pass_key_env: None,
        commit,
        confirm_backup: backup,
    };
    let mut out = Vec::new();
    let mut asked = Vec::new();
    let mut confirm = |id: &str| -> anyhow::Result<bool> {
        asked.push(id.to_owned());
        Ok(answer)
    };
    let result = changes::apply_proposal(store, id, &options, &mut out, &mut confirm).await;
    (result, String::from_utf8(out).unwrap(), asked)
}

async fn check(uri: String, other_store_uri: String, directory: &std::path::Path) {
    let uri = uri.as_str();
    let store = ProposalStore::new(directory.join("proposals"));
    let alice = id_of(uri, "alice").await;
    let bob = id_of(uri, "bob").await;
    let carol = id_of(uri, "carol").await;
    let key = id_of(uri, "k").await;

    // Creating a proposal stores no old values and says nothing about the data.
    let id = propose(
        uri,
        &store,
        json!([
            {"op": "set_json", "profile": "main", "id": alice, "pointer": "/state", "value": "done"},
            {"op": "set_json", "profile": "main", "id": alice, "pointer": "/added", "value": [1, 2]},
            {"op": "set_tag", "profile": "main", "id": alice, "name": "state", "value": "done", "plaintext": true},
            {"op": "remove_tag", "profile": "main", "id": alice, "name": "owner"},
            {"op": "set_expiry", "profile": "main", "id": alice, "expiry": "2099-01-02 03:04:05"},
            {"op": "remove", "profile": "main", "id": bob},
            {"op": "insert", "profile": "main", "category": "people", "name": "dave",
             "value": {"state": "new"}, "tags": [{"name": "state", "value": "new", "plaintext": true}]}
        ]),
    )
    .await
    .unwrap();
    let saved =
        std::fs::read_to_string(directory.join("proposals").join(format!("{id}.json"))).unwrap();
    for old in ["OLD-SECRET", "OWNER-X", "active"] {
        assert!(!saved.contains(old), "{old} must not be stored:\n{saved}");
    }
    assert!(
        saved.contains("\"new\"") && saved.contains("Fix states"),
        "proposed values are kept"
    );
    assert_eq!(
        store.load(&id).unwrap().expected.len(),
        2,
        "one fingerprint per edited entry"
    );

    // Malformed or impossible edits are refused up front, with messages that carry no data.
    for (ops, why) in [
        (
            json!([{"op": "remove", "profile": "nope", "id": alice}]),
            "profile",
        ),
        (
            json!([{"op": "remove", "profile": "main", "id": 999999}]),
            "No entry",
        ),
        (
            json!([{"op": "remove", "profile": "main", "id": key}]),
            "key-manager",
        ),
        (
            json!([{"op": "remove", "profile": "main", "id": carol}]),
            "expired",
        ),
        (
            json!([{"op": "set_json", "profile": "main", "id": alice, "pointer": "/a/b/c", "value": 1}]),
            "parent",
        ),
        (
            json!([{"op": "remove_tag", "profile": "main", "id": bob, "name": "none"}]),
            "no encrypted tag",
        ),
        (
            json!([{"op": "set_expiry", "profile": "main", "id": bob, "expiry": "soon"}]),
            "Expiry",
        ),
        (json!([]), "at least one"),
    ] {
        let error = format!("{:#}", propose(uri, &store, ops.clone()).await.unwrap_err());
        assert!(error.contains(why), "{ops}: {error}");
        assert!(
            !error.contains("OLD-SECRET") && !error.contains("OWNER-X"),
            "{error}"
        );
    }
    // Guesses are not confirmed or denied: a no-op and a name that exists are both accepted.
    let noop = propose(
        uri,
        &store,
        json!([{"op": "set_json", "profile": "main", "id": bob, "pointer": "/state", "value": "active"}]),
    )
    .await;
    let existing = propose(
        uri,
        &store,
        json!([{"op": "insert", "profile": "main", "category": "people", "name": "alice", "value": {}}]),
    )
    .await;
    assert!(noop.is_ok() && existing.is_ok());

    // Review shows the real before and after.
    let mut source = Source::open(uri, None).await.unwrap();
    let mut shown = Vec::new();
    changes::review(&store, &id, &mut source, &mut shown)
        .await
        .unwrap();
    let shown = String::from_utf8(shown).unwrap();
    for expected in [
        "Fix states",
        "They are stuck",
        "replace",
        "-  \"state\": \"active\"",
        "+  \"state\": \"done\"",
        "OLD-SECRET-bob",
        "- tag owner=OWNER-X",
        "+ tag ~state=done",
        "- tag ~state=active",
        "expiry (none) -> 2099-01-02 03:04:05",
        "insert",
        "remove",
    ] {
        assert!(shown.contains(expected), "missing {expected:?} in\n{shown}");
    }
    // Reviewing the no-op and the colliding insert explains what a person needs to know.
    let mut again = Vec::new();
    changes::review(&store, &noop.unwrap(), &mut source, &mut again)
        .await
        .unwrap();
    assert!(String::from_utf8(again).unwrap().contains("change nothing"));
    assert!(
        changes::review(&store, &existing.unwrap(), &mut source, &mut Vec::new())
            .await
            .unwrap_err()
            .to_string()
            .contains("already exists")
    );
    drop(source);

    // Nothing is written without every safeguard.
    let unchanged = || async { value_of(uri, "alice").await.unwrap()["state"].clone() };
    let (result, out, asked) = apply(&store, &id, uri, Some(uri), false, false, true).await;
    assert!(!result.unwrap() && out.contains("Dry run") && asked.is_empty());
    let (result, _, asked) = apply(&store, &id, uri, Some(uri), true, false, true).await;
    assert!(result.unwrap_err().to_string().contains("--confirm-backup") && asked.is_empty());
    let (result, _, asked) = apply(&store, &id, uri, None, true, true, true).await;
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("ASKAR_EXPLORER_WRITE_URI")
            && asked.is_empty()
    );
    let (result, _, asked) =
        apply(&store, &id, uri, Some(&other_store_uri), true, true, true).await;
    assert!(result.unwrap_err().to_string().contains("different store") && asked.is_empty());
    let (result, _, asked) = apply(&store, &id, uri, Some(uri), true, true, false).await;
    assert!(result.unwrap_err().to_string().contains("Not confirmed"));
    assert_eq!(
        asked,
        std::slice::from_ref(&id),
        "the person is asked to type the proposal id"
    );
    assert_eq!(unchanged().await, "active");
    assert_eq!(store.load(&id).unwrap().status, Status::Pending);

    // A change to an entry after the proposal blocks it.
    let backend = uri
        .open_backend(None, PassKey::empty(), None)
        .await
        .unwrap();
    let mut session = backend.session(None, false).unwrap();
    let edited = SecretBytes::from(
        json!({"state": "active", "note": "EDITED"})
            .to_string()
            .into_bytes(),
    );
    session
        .update(
            EntryKind::Item,
            EntryOperation::Replace,
            "people",
            "bob",
            Some(&edited),
            Some(&[]),
            None,
        )
        .await
        .unwrap();
    session.close(true).await.unwrap();
    backend.close().await.unwrap();
    let (result, _, _) = apply(&store, &id, uri, Some(uri), true, true, true).await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("changed since the proposal"));
    assert_eq!(unchanged().await, "active", "nothing was written");

    // A fresh proposal applies once it is confirmed, and only once.
    let fresh = propose(
        uri,
        &store,
        json!([
            {"op": "set_json", "profile": "main", "id": alice, "pointer": "/state", "value": "done"},
            {"op": "set_tag", "profile": "main", "id": alice, "name": "state", "value": "done", "plaintext": true},
            {"op": "remove", "profile": "main", "id": bob},
            {"op": "insert", "profile": "main", "category": "people", "name": "dave", "value": {"state": "new"}}
        ]),
    )
    .await
    .unwrap();
    let (result, out, asked) = apply(&store, &fresh, uri, Some(uri), true, true, true).await;
    assert!(result.unwrap(), "{out}");
    assert_eq!(asked, std::slice::from_ref(&fresh));
    assert!(out.contains("Applied 3 change(s)"), "{out}");
    let alice_now = value_of(uri, "alice").await.unwrap();
    assert_eq!(
        alice_now,
        json!({"state": "done", "note": "OLD-SECRET-alice", "n": 1})
    );
    assert_eq!(
        alice_now.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["state", "note", "n"],
        "field order is preserved"
    );
    assert!(value_of(uri, "bob").await.is_none());
    assert_eq!(
        value_of(uri, "dave").await.unwrap(),
        json!({"state": "new"})
    );
    assert_eq!(store.load(&fresh).unwrap().status, Status::Applied);
    let (result, _, _) = apply(&store, &fresh, uri, Some(uri), true, true, true).await;
    assert!(result.unwrap_err().to_string().contains("already"));
    let log = std::fs::read_to_string(directory.join("proposals").join("changes.log")).unwrap();
    assert!(log.contains(&fresh) && !log.contains("OLD-SECRET") && !log.contains("done"));
    let mut source = Source::open(uri, None).await.unwrap();
    let profile = source.select_profiles(None).unwrap().remove(0);
    let tags = source
        .scan(
            &profile,
            &Query {
                name: Some("alice".into()),
                ..Default::default()
            },
            0,
            1,
        )
        .await
        .unwrap()
        .remove(0)
        .tags;
    let tags: Vec<_> = tags.into_iter().map(Result::unwrap).collect();
    assert!(tags.contains(&EntryTag::Plaintext("state".into(), "done".into())));
    assert!(tags.contains(&EntryTag::Encrypted("owner".into(), "OWNER-X".into())));

    // Rejecting ends a proposal.
    let other = propose(
        uri,
        &store,
        json!([{"op": "set_tag", "profile": "main", "id": alice, "name": "x", "value": "y"}]),
    )
    .await
    .unwrap();
    store.finish(&other, Status::Rejected).unwrap();
    let (result, _, _) = apply(&store, &other, uri, Some(uri), true, true, true).await;
    assert!(result.unwrap_err().to_string().contains("already"));
}

async fn provision_sqlite(path: &std::path::Path) -> String {
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
    format!("sqlite://{}", path.display())
}

#[tokio::test]
async fn sqlite_proposals_are_reviewed_confirmed_and_applied() {
    let directory = tempfile::tempdir().unwrap();
    let uri = provision_sqlite(&directory.path().join("store.db")).await;
    let other = provision_sqlite(&directory.path().join("other.db")).await;
    check(uri, other, directory.path()).await;
}

#[tokio::test]
async fn postgres_proposals_when_configured() {
    let Ok(base_uri) = std::env::var("POSTGRES_URL") else {
        return;
    };
    let directory = tempfile::tempdir().unwrap();
    let schemas = [
        format!("chg_a_{}", std::process::id()),
        format!("chg_b_{}", std::process::id()),
    ];
    let mut uris = Vec::new();
    for schema in &schemas {
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
        uris.push(uri);
    }
    let checked = tokio::spawn({
        let (a, b, path) = (
            uris[0].clone(),
            uris[1].clone(),
            directory.path().to_owned(),
        );
        async move { check(a, b, &path).await }
    })
    .await;
    let mut cleanup = sqlx::PgConnection::connect(&base_uri).await.unwrap();
    for schema in &schemas {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA \"{schema}\" CASCADE"
        )))
        .execute(&mut cleanup)
        .await
        .unwrap();
    }
    checked.unwrap();
}

#[test]
fn ops_are_typed_and_strict() {
    let op: Op = serde_json::from_value(json!({"op": "remove", "profile": "p", "id": 1})).unwrap();
    assert!(matches!(op, Op::Remove { .. }));
    assert!(serde_json::from_value::<Op>(
        json!({"op": "remove", "profile": "p", "id": 1, "extra": 1})
    )
    .is_err());
}
