use askar_storage::{
    crypto::buffer::SecretBytes,
    entry::{EntryKind, EntryOperation, EntryTag},
    inspect::{ExpiryFilter, InspectionKey, Inspector, RawFilter},
    Backend, BackendSession, ManageBackend, PassKey, StoreKeyMethod,
};

type SeedRow<'a> = (EntryKind, &'a str, &'a str, Vec<EntryTag>, Option<i64>);

async fn seed(backend: &impl Backend) {
    let mut session = backend.session(None, false).unwrap();
    let value = SecretBytes::from(b"{}".as_slice());
    let rows: [SeedRow<'_>; 4] = [
        (
            EntryKind::Item,
            "records",
            "a",
            vec![
                EntryTag::Plaintext("status".into(), "active".into()),
                EntryTag::Encrypted("owner".into(), "alice".into()),
            ],
            None,
        ),
        (
            EntryKind::Item,
            "records",
            "b",
            vec![EntryTag::Plaintext("status".into(), "done".into())],
            None,
        ),
        (EntryKind::Item, "other", "c", vec![], Some(-1000)),
        (EntryKind::Kms, "keys", "k", vec![], None),
    ];
    for (kind, category, name, tags, expiry) in rows {
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

macro_rules! filter_tests {
    ($module:ident, $reads:path) => {
        async fn $module(uri: &str) {
            use $reads as reads;
            let mut db = reads::open(uri).await.unwrap();
            let key_reference = reads::key_reference(&mut db).await.unwrap();
            assert_eq!(key_reference, "none");
            let profile = reads::profiles(&mut db).await.unwrap().remove(0);
            let key = InspectionKey::resolve(&key_reference, PassKey::empty()).unwrap();
            let inspector: Inspector = key.unlock(profile.profile_key.unwrap()).unwrap();
            let names = |items: Vec<askar_storage::inspect::RawItem>| -> Vec<String> {
                items
                    .into_iter()
                    .map(|item| inspector.decrypt(item).name.unwrap())
                    .collect()
            };
            let scan = |filter: RawFilter| {
                let id = profile.id;
                async move { (id, filter) }
            };

            let (id, filter) = scan(RawFilter::default()).await;
            let all = reads::scan(&mut db, Some(id), &filter, 0, 100)
                .await
                .unwrap();
            assert_eq!(names(all), ["a", "b", "c", "k"]);

            let filter = RawFilter {
                category: Some(inspector.encrypt_category("records").unwrap()),
                ..Default::default()
            };
            let found = reads::scan(&mut db, Some(id), &filter, 0, 100)
                .await
                .unwrap();
            assert_eq!(names(found), ["a", "b"]);

            let filter = RawFilter {
                category: Some(inspector.encrypt_category("records").unwrap()),
                name: Some(inspector.encrypt_name("b").unwrap()),
                ..Default::default()
            };
            let found = reads::scan(&mut db, Some(id), &filter, 0, 100)
                .await
                .unwrap();
            assert_eq!(names(found), ["b"]);

            let filter = RawFilter {
                tags: vec![inspector.tag_filter("status", "active", true).unwrap()],
                ..Default::default()
            };
            let found = reads::scan(&mut db, Some(id), &filter, 0, 100)
                .await
                .unwrap();
            assert_eq!(names(found), ["a"]);

            let filter = RawFilter {
                tags: vec![
                    inspector.tag_filter("owner", "alice", false).unwrap(),
                    inspector.tag_filter("status", "active", true).unwrap(),
                ],
                ..Default::default()
            };
            let found = reads::scan(&mut db, Some(id), &filter, 0, 100)
                .await
                .unwrap();
            assert_eq!(names(found), ["a"]);

            let filter = RawFilter {
                tags: vec![inspector.tag_filter("owner", "bob", false).unwrap()],
                ..Default::default()
            };
            assert!(reads::scan(&mut db, Some(id), &filter, 0, 100)
                .await
                .unwrap()
                .is_empty());

            let filter = RawFilter {
                expiry: ExpiryFilter::ExpiredOnly,
                ..Default::default()
            };
            let found = reads::scan(&mut db, Some(id), &filter, 0, 100)
                .await
                .unwrap();
            assert_eq!(names(found), ["c"]);
            let filter = RawFilter {
                expiry: ExpiryFilter::LiveOnly,
                ..Default::default()
            };
            let found = reads::scan(&mut db, Some(id), &filter, 0, 100)
                .await
                .unwrap();
            assert_eq!(names(found), ["a", "b", "k"]);

            let filter = RawFilter {
                kind: Some(1),
                ..Default::default()
            };
            let found = reads::scan(&mut db, Some(id), &filter, 0, 100)
                .await
                .unwrap();
            assert_eq!(names(found), ["k"]);

            let first = reads::page(&mut db, id, 0, 2).await.unwrap();
            let after = first.last().unwrap().id;
            let second = reads::page(&mut db, id, after, 2).await.unwrap();
            assert_eq!((first.len(), second.len()), (2, 2));
            let target = second[0].id;
            let fetched = reads::fetch(&mut db, id, target).await.unwrap().unwrap();
            assert_eq!(fetched.id, target);
            assert!(reads::fetch(&mut db, id, i64::MAX).await.unwrap().is_none());
            assert!(reads::page(&mut db, id, 0, 0).await.is_err());

            let stats = reads::stats(&mut db).await.unwrap();
            let mut summary: Vec<(String, i64, i64, i64)> = stats
                .into_iter()
                .map(|stat| {
                    (
                        inspector.decrypt_category(stat.category).unwrap(),
                        stat.kind,
                        stat.items,
                        stat.expired,
                    )
                })
                .collect();
            summary.sort();
            assert_eq!(
                summary,
                [
                    ("keys".to_owned(), 1, 1, 0),
                    ("other".to_owned(), 2, 1, 1),
                    ("records".to_owned(), 2, 2, 0),
                ]
            );
        }
    };
}

filter_tests!(check_sqlite, askar_storage::inspect::sqlite);
filter_tests!(check_postgres, askar_storage::inspect::postgres);

#[tokio::test]
async fn sqlite_filters_expiry_tags_paging_and_stats() {
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
    check_sqlite(&format!("sqlite://{}", path.display())).await;
}

#[tokio::test]
async fn postgres_filters_expiry_tags_paging_and_stats_when_configured() {
    let Ok(base_uri) = std::env::var("POSTGRES_URL") else {
        return;
    };
    let schema = format!("filters_{}", std::process::id());
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
    let result = tokio::spawn({
        let uri = uri.clone();
        async move { check_postgres(&uri).await }
    })
    .await;
    // Drop the schema through the inspection role's own database, then surface any failure.
    let mut cleanup = sqlx::PgConnection::connect(&base_uri).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&mut cleanup)
    .await
    .unwrap();
    result.unwrap();
}

use sqlx::Connection;
