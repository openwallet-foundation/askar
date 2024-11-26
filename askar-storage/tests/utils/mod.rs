use askar_storage::{
    any::AnyBackend,
    entry::{Entry, EntryKind, EntryOperation, EntryTag, TagFilter},
    Backend, BackendSession, ErrorKind,
};

use tokio::task::spawn;

const ERR_PROFILE: &str = "Error creating profile";
const ERR_SESSION: &str = "Error starting session";
const ERR_TRANSACTION: &str = "Error starting transaction";
const ERR_COMMIT: &str = "Error committing transaction";
const ERR_COUNT: &str = "Error performing count";
const ERR_FETCH: &str = "Error fetching test row";
const ERR_FETCH_ALL: &str = "Error fetching all test rows";
const ERR_REQ_ROW: &str = "Expected row";
const ERR_REQ_ERR: &str = "Expected error";
const ERR_INSERT: &str = "Error inserting test row";
const ERR_REPLACE: &str = "Error replacing test row";
const ERR_REMOVE_ALL: &str = "Error removing test rows";
const ERR_SCAN: &str = "Error starting scan";
const ERR_SCAN_NEXT: &str = "Error fetching scan rows";

pub async fn db_create_remove_profile(db: AnyBackend) {
    let profile = db.create_profile(None).await.expect(ERR_PROFILE);
    let mut sess = db.session(Some(profile.clone()), false).expect(ERR_PROFILE);
    sess.ping().await.expect(ERR_PROFILE);
    sess.close(false).await.unwrap();
    assert!(db
        .remove_profile(profile.clone())
        .await
        .expect("Error removing profile"));
    let mut sess = db.session(Some(profile.clone()), false).expect(ERR_PROFILE);
    sess.ping()
        .await
        .expect_err("Expected connection to removed session to fail");
    sess.close(false).await.unwrap();
    assert!(!db
        .remove_profile("not a profile".to_string())
        .await
        .expect("Error removing profile"));
}

pub async fn db_fetch_fail(db: AnyBackend) {
    let mut conn = db.session(None, false).expect(ERR_SESSION);
    let result = conn
        .fetch(EntryKind::Item, "cat", "name", false)
        .await
        .expect(ERR_FETCH);
    assert!(result.is_none());
}

pub async fn db_insert_fetch(db: AnyBackend) {
    let test_row = Entry::new(
        EntryKind::Item,
        "category",
        "name",
        "value",
        vec![
            EntryTag::Encrypted("t1".to_string(), "v1".to_string()),
            EntryTag::Plaintext("t2".to_string(), "v2".to_string()),
        ],
    );

    let mut conn = db.session(None, false).expect(ERR_SESSION);

    conn.update(
        EntryKind::Item,
        EntryOperation::Insert,
        &test_row.category,
        &test_row.name,
        Some(&test_row.value),
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    let row = conn
        .fetch(EntryKind::Item, &test_row.category, &test_row.name, false)
        .await
        .expect(ERR_FETCH)
        .expect(ERR_REQ_ROW);
    assert_eq!(row, test_row);

    let rows = conn
        .fetch_all(
            Some(EntryKind::Item),
            Some(&test_row.category),
            None,
            None,
            None,
            false,
            false,
        )
        .await
        .expect(ERR_FETCH_ALL);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0], test_row);
}

pub async fn db_insert_duplicate(db: AnyBackend) {
    let test_row = Entry::new(EntryKind::Item, "category", "name", "value", Vec::new());

    let mut conn = db.session(None, false).expect(ERR_SESSION);

    conn.update(
        EntryKind::Item,
        EntryOperation::Insert,
        &test_row.category,
        &test_row.name,
        Some(&test_row.value),
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    let err = conn
        .update(
            EntryKind::Item,
            EntryOperation::Insert,
            &test_row.category,
            &test_row.name,
            Some(&test_row.value),
            Some(test_row.tags.as_slice()),
            None,
        )
        .await
        .expect_err(ERR_REQ_ERR);
    assert_eq!(err.kind(), ErrorKind::Duplicate);
}

pub async fn db_insert_remove(db: AnyBackend) {
    let test_row = Entry::new(EntryKind::Item, "category", "name", "value", Vec::new());

    let mut conn = db.session(None, false).expect(ERR_SESSION);

    conn.update(
        EntryKind::Item,
        EntryOperation::Insert,
        &test_row.category,
        &test_row.name,
        Some(&test_row.value),
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    conn.update(
        EntryKind::Item,
        EntryOperation::Remove,
        &test_row.category,
        &test_row.name,
        None,
        None,
        None,
    )
    .await
    .expect(ERR_REQ_ROW);
}

pub async fn db_remove_missing(db: AnyBackend) {
    let mut conn = db.session(None, false).expect(ERR_SESSION);

    let err = conn
        .update(
            EntryKind::Item,
            EntryOperation::Remove,
            "cat",
            "name",
            None,
            None,
            None,
        )
        .await
        .expect_err(ERR_REQ_ERR);
    assert_eq!(err.kind(), ErrorKind::NotFound);
}

pub async fn db_replace_fetch(db: AnyBackend) {
    let test_row = Entry::new(EntryKind::Item, "category", "name", "value", Vec::new());

    let mut conn = db.session(None, false).expect(ERR_SESSION);

    conn.update(
        EntryKind::Item,
        EntryOperation::Insert,
        &test_row.category,
        &test_row.name,
        Some(&test_row.value),
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    let mut replace_row = test_row.clone();
    replace_row.value = "new value".into();
    conn.update(
        EntryKind::Item,
        EntryOperation::Replace,
        &replace_row.category,
        &replace_row.name,
        Some(&replace_row.value),
        Some(replace_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_REPLACE);

    let row = conn
        .fetch(
            EntryKind::Item,
            &replace_row.category,
            &replace_row.name,
            false,
        )
        .await
        .expect(ERR_FETCH)
        .expect(ERR_REQ_ROW);
    assert_eq!(row, replace_row);
}

pub async fn db_replace_missing(db: AnyBackend) {
    let test_row = Entry::new(EntryKind::Item, "category", "name", "value", Vec::new());

    let mut conn = db.session(None, false).expect(ERR_SESSION);

    let err = conn
        .update(
            EntryKind::Item,
            EntryOperation::Replace,
            &test_row.category,
            &test_row.name,
            Some(&test_row.value),
            Some(test_row.tags.as_slice()),
            None,
        )
        .await
        .expect_err(ERR_REQ_ERR);
    assert_eq!(err.kind(), ErrorKind::NotFound);
}

pub async fn db_count(db: AnyBackend) {
    let category = "category".to_string();
    let test_rows = [Entry::new(
        EntryKind::Item,
        &category,
        "name",
        "value",
        Vec::new(),
    )];

    let mut conn = db.session(None, false).expect(ERR_SESSION);

    for upd in test_rows.iter() {
        conn.update(
            EntryKind::Item,
            EntryOperation::Insert,
            &upd.category,
            &upd.name,
            Some(&upd.value),
            Some(upd.tags.as_slice()),
            None,
        )
        .await
        .expect(ERR_INSERT);
    }

    let tag_filter = None;
    let count = conn
        .count(Some(EntryKind::Item), Some(&category), tag_filter)
        .await
        .expect(ERR_COUNT);
    assert_eq!(count, 1);

    let tag_filter = Some(TagFilter::is_eq("sometag", "someval"));
    let count = conn
        .count(Some(EntryKind::Item), Some(&category), tag_filter)
        .await
        .expect(ERR_COUNT);
    assert_eq!(count, 0);
}

pub async fn db_count_exist(db: AnyBackend) {
    let test_row = Entry::new(
        EntryKind::Item,
        "category",
        "name",
        "value",
        vec![
            EntryTag::Encrypted("enc".to_string(), "v1".to_string()),
            EntryTag::Plaintext("plain".to_string(), "v2".to_string()),
        ],
    );

    let mut conn = db.session(None, false).expect(ERR_SESSION);

    conn.update(
        EntryKind::Item,
        EntryOperation::Insert,
        &test_row.category,
        &test_row.name,
        Some(&test_row.value),
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    assert_eq!(
        conn.count(Some(EntryKind::Item), Some(&test_row.category), None)
            .await
            .expect(ERR_COUNT),
        1
    );

    assert_eq!(
        conn.count(Some(EntryKind::Kms), Some(&test_row.category), None)
            .await
            .expect(ERR_COUNT),
        0
    );

    assert_eq!(
        conn.count(
            Some(EntryKind::Item),
            Some(&test_row.category),
            Some(TagFilter::exist(vec!["enc".to_string()]))
        )
        .await
        .expect(ERR_COUNT),
        1
    );

    assert_eq!(
        conn.count(
            Some(EntryKind::Item),
            Some(&test_row.category),
            Some(TagFilter::exist(vec!["~plain".to_string()]))
        )
        .await
        .expect(ERR_COUNT),
        1
    );

    assert_eq!(
        conn.count(
            Some(EntryKind::Item),
            Some(&test_row.category),
            Some(TagFilter::exist(vec!["~enc".to_string()]))
        )
        .await
        .expect(ERR_COUNT),
        0
    );

    assert_eq!(
        conn.count(
            Some(EntryKind::Item),
            Some(&test_row.category),
            Some(TagFilter::exist(vec!["plain".to_string()]))
        )
        .await
        .expect(ERR_COUNT),
        0
    );

    assert_eq!(
        conn.count(
            Some(EntryKind::Item),
            Some(&test_row.category),
            Some(TagFilter::exist(vec!["other".to_string()]))
        )
        .await
        .expect(ERR_COUNT),
        0
    );

    assert_eq!(
        conn.count(
            Some(EntryKind::Item),
            Some(&test_row.category),
            Some(TagFilter::exist(vec![
                "enc".to_string(),
                "other".to_string()
            ]))
        )
        .await
        .expect(ERR_COUNT),
        0
    );

    assert_eq!(
        conn.count(
            Some(EntryKind::Item),
            Some(&test_row.category),
            Some(TagFilter::all_of(vec![
                TagFilter::exist(vec!["enc".to_string()]),
                TagFilter::exist(vec!["~plain".to_string()])
            ]))
        )
        .await
        .expect(ERR_COUNT),
        1
    );

    assert_eq!(
        conn.count(
            Some(EntryKind::Item),
            Some(&test_row.category),
            Some(TagFilter::any_of(vec![
                TagFilter::exist(vec!["~enc".to_string()]),
                TagFilter::exist(vec!["~plain".to_string()])
            ]))
        )
        .await
        .expect(ERR_COUNT),
        1
    );

    assert_eq!(
        conn.count(
            Some(EntryKind::Item),
            Some(&test_row.category),
            Some(TagFilter::all_of(vec![
                TagFilter::exist(vec!["~enc".to_string()]),
                TagFilter::exist(vec!["~plain".to_string()])
            ]))
        )
        .await
        .expect(ERR_COUNT),
        0
    );

    assert_eq!(
        conn.count(
            Some(EntryKind::Item),
            Some(&test_row.category),
            Some(TagFilter::negate(TagFilter::exist(vec![
                "enc".to_string(),
                "other".to_string()
            ]),))
        )
        .await
        .expect(ERR_COUNT),
        0
    );
}

pub async fn db_scan(db: AnyBackend) {
    let category = "category".to_string();
    let test_rows = vec![Entry::new(
        EntryKind::Item,
        &category,
        "name",
        "value",
        vec![
            EntryTag::Encrypted("t1".to_string(), "v1".to_string()),
            EntryTag::Plaintext("t2".to_string(), "v2".to_string()),
        ],
    )];

    let mut conn = db.session(None, false).expect(ERR_SESSION);

    for upd in test_rows.iter() {
        conn.update(
            EntryKind::Item,
            EntryOperation::Insert,
            &upd.category,
            &upd.name,
            Some(&upd.value),
            Some(upd.tags.as_slice()),
            None,
        )
        .await
        .expect(ERR_INSERT);
    }
    drop(conn);

    let tag_filter = None;
    let offset = None;
    let limit = None;
    let mut scan = db
        .scan(
            None,
            Some(EntryKind::Item),
            Some(category.clone()),
            tag_filter,
            offset,
            limit,
            None,
            false,
        )
        .await
        .expect(ERR_SCAN);
    let rows = scan.fetch_next().await.expect(ERR_SCAN_NEXT);
    assert_eq!(rows, Some(test_rows));
    let rows = scan.fetch_next().await.expect(ERR_SCAN_NEXT);
    assert_eq!(rows, None);

    let tag_filter = Some(TagFilter::is_eq("sometag", "someval"));
    let mut scan = db
        .scan(
            None,
            Some(EntryKind::Item),
            Some(category.clone()),
            tag_filter,
            offset,
            limit,
            None,
            false,
        )
        .await
        .expect(ERR_SCAN);
    let rows = scan.fetch_next().await.expect(ERR_SCAN_NEXT);
    assert_eq!(rows, None);
}

pub async fn db_remove_all(db: AnyBackend) {
    let test_rows = vec![
        Entry::new(
            EntryKind::Item,
            "category",
            "item1",
            "value",
            vec![
                EntryTag::Encrypted("t1".to_string(), "del".to_string()),
                EntryTag::Plaintext("t2".to_string(), "del".to_string()),
            ],
        ),
        Entry::new(
            EntryKind::Item,
            "category",
            "item2",
            "value",
            vec![
                EntryTag::Encrypted("t1".to_string(), "del".to_string()),
                EntryTag::Plaintext("t2".to_string(), "del".to_string()),
            ],
        ),
        Entry::new(
            EntryKind::Item,
            "category",
            "item3",
            "value",
            vec![
                EntryTag::Encrypted("t1".to_string(), "keep".to_string()),
                EntryTag::Plaintext("t2".to_string(), "keep".to_string()),
            ],
        ),
    ];

    let mut conn = db.session(None, false).expect(ERR_SESSION);

    for test_row in test_rows.iter() {
        conn.update(
            EntryKind::Item,
            EntryOperation::Insert,
            &test_row.category,
            &test_row.name,
            Some(&test_row.value),
            Some(test_row.tags.as_slice()),
            None,
        )
        .await
        .expect(ERR_INSERT);
    }

    // could detect that a second transaction would block here?
    // depends on the backend. just checking that no SQL errors occur for now.
    let removed = conn
        .remove_all(
            Some(EntryKind::Item),
            Some("category"),
            Some(TagFilter::all_of(vec![
                TagFilter::is_eq("t1", "del"),
                TagFilter::is_eq("~t2", "del"),
            ])),
        )
        .await
        .expect(ERR_REMOVE_ALL);
    assert_eq!(removed, 2);
}

pub async fn db_txn_rollback(db: AnyBackend) {
    let test_row = Entry::new(EntryKind::Item, "category", "name", "value", Vec::new());

    let mut conn = db.session(None, true).expect(ERR_TRANSACTION);

    conn.update(
        EntryKind::Item,
        EntryOperation::Insert,
        &test_row.category,
        &test_row.name,
        Some(&test_row.value),
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    conn.close(false)
        .await
        .expect("Error rolling back transaction");

    let mut conn = db.session(None, false).expect("Error starting new session");

    let row = conn
        .fetch(EntryKind::Item, &test_row.category, &test_row.name, false)
        .await
        .expect("Error fetching test row");
    assert_eq!(row, None);
}

pub async fn db_txn_drop(db: AnyBackend) {
    let test_row = Entry::new(EntryKind::Item, "category", "name", "value", Vec::new());

    let mut conn = db
        .session(None, true)
        .expect("Error starting new transaction");

    conn.update(
        EntryKind::Item,
        EntryOperation::Insert,
        &test_row.category,
        &test_row.name,
        Some(&test_row.value),
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    drop(conn);

    let mut conn = db.session(None, false).expect("Error starting new session");

    let row = conn
        .fetch(EntryKind::Item, &test_row.category, &test_row.name, false)
        .await
        .expect("Error fetching test row");
    assert_eq!(row, None);
}

// test that session does NOT have transaction rollback behaviour
pub async fn db_session_drop(db: AnyBackend) {
    let test_row = Entry::new(EntryKind::Item, "category", "name", "value", Vec::new());

    let mut conn = db.session(None, false).expect(ERR_SESSION);

    conn.update(
        EntryKind::Item,
        EntryOperation::Insert,
        &test_row.category,
        &test_row.name,
        Some(&test_row.value),
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    drop(conn);

    let mut conn = db.session(None, false).expect(ERR_SESSION);

    let row = conn
        .fetch(EntryKind::Item, &test_row.category, &test_row.name, false)
        .await
        .expect(ERR_FETCH);
    assert_eq!(row, Some(test_row));
}

pub async fn db_txn_commit(db: AnyBackend) {
    let test_row = Entry::new(EntryKind::Item, "category", "name", "value", Vec::new());

    let mut conn = db.session(None, true).expect(ERR_TRANSACTION);

    conn.update(
        EntryKind::Item,
        EntryOperation::Insert,
        &test_row.category,
        &test_row.name,
        Some(&test_row.value),
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    conn.close(true).await.expect(ERR_COMMIT);

    let mut conn = db.session(None, false).expect(ERR_SESSION);

    let row = conn
        .fetch(EntryKind::Item, &test_row.category, &test_row.name, false)
        .await
        .expect(ERR_FETCH);
    assert_eq!(row, Some(test_row));
}

pub async fn db_txn_fetch_for_update(db: AnyBackend) {
    let test_row = Entry::new(EntryKind::Item, "category", "name", "value", Vec::new());

    let mut conn = db.session(None, true).expect(ERR_TRANSACTION);

    conn.update(
        EntryKind::Item,
        EntryOperation::Insert,
        &test_row.category,
        &test_row.name,
        Some(&test_row.value),
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    // could detect that a second transaction would block here?
    // depends on the backend. just checking that no SQL errors occur for now.
    let row = conn
        .fetch(EntryKind::Item, &test_row.category, &test_row.name, true)
        .await
        .expect(ERR_FETCH)
        .expect(ERR_REQ_ROW);
    assert_eq!(row, test_row);

    let rows = conn
        .fetch_all(
            Some(EntryKind::Item),
            Some(&test_row.category),
            None,
            Some(2),
            None,
            false,
            true,
        )
        .await
        .expect(ERR_FETCH_ALL);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0], test_row);

    conn.close(true).await.expect(ERR_COMMIT);
}

pub async fn db_txn_contention(db: AnyBackend) {
    let test_row = Entry::new(
        EntryKind::Item,
        "category",
        "count",
        "0",
        vec![
            EntryTag::Encrypted("t1".to_string(), "v1".to_string()),
            EntryTag::Plaintext("t2".to_string(), "v2".to_string()),
        ],
    );

    let mut conn = db.session(None, true).expect(ERR_TRANSACTION);

    conn.update(
        EntryKind::Item,
        EntryOperation::Insert,
        &test_row.category,
        &test_row.name,
        Some(&test_row.value),
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    conn.close(true).await.expect(ERR_COMMIT);

    const TASKS: usize = 10;
    const INC: usize = 1000;

    async fn inc(db: AnyBackend, category: String, name: String) -> Result<(), &'static str> {
        // try to avoid panics in this section, as they will be raised on a tokio worker thread
        for _ in 0..INC {
            let mut conn = db.session(None, true).expect(ERR_TRANSACTION);
            let row = conn
                .fetch(EntryKind::Item, &category, &name, true)
                .await
                .map_err(|e| {
                    log::error!("{:?}", e);
                    ERR_FETCH
                })?
                .ok_or(ERR_REQ_ROW)?;
            let val: usize = str::parse(row.value.as_opt_str().ok_or("Non-string counter value")?)
                .map_err(|_| "Error parsing counter value")?;
            conn.update(
                EntryKind::Item,
                EntryOperation::Replace,
                &category,
                &name,
                Some(format!("{}", val + 1).as_bytes()),
                Some(row.tags.as_slice()),
                None,
            )
            .await
            .map_err(|e| {
                log::error!("{:?}", e);
                ERR_REPLACE
            })?;
            conn.close(true).await.map_err(|_| ERR_COMMIT)?;
        }
        Ok(())
    }

    let mut tasks = vec![];
    for _ in 0..TASKS {
        tasks.push(spawn(inc(
            db.clone(),
            test_row.category.clone(),
            test_row.name.clone(),
        )));
    }

    // JoinSet is not stable yet, just await all the tasks
    for task in tasks {
        if let Err(s) = task.await.unwrap() {
            panic!("Error in concurrent update task: {}", s);
        }
    }

    // check the total
    let mut conn = db.session(None, false).expect(ERR_SESSION);
    let row = conn
        .fetch(EntryKind::Item, &test_row.category, &test_row.name, false)
        .await
        .expect(ERR_FETCH)
        .expect(ERR_REQ_ROW);
    assert_eq!(row.value, format!("{}", TASKS * INC).as_bytes());
}

pub async fn db_list_profiles(db: AnyBackend) {
    let p_active = db.get_active_profile();
    assert_eq!(vec![p_active.clone()], db.list_profiles().await.unwrap());

    let p_new = db.create_profile(None).await.unwrap();
    let mut profs = vec![p_active, p_new];
    profs.sort();
    let mut found = db.list_profiles().await.unwrap();
    found.sort();
    assert_eq!(profs, found);
}

pub async fn db_get_set_default_profile(db: AnyBackend) {
    let p_default = db.get_default_profile().await.unwrap();
    let p_new = db.create_profile(None).await.unwrap();
    assert_ne!(p_new, p_default);
    db.set_default_profile(p_new.clone()).await.unwrap();
    assert_eq!(db.get_default_profile().await.unwrap(), p_new);
}

pub async fn db_import_scan(db: AnyBackend) {
    let test_rows = vec![Entry::new(
        EntryKind::Item,
        "category",
        "name",
        "value",
        vec![
            EntryTag::Encrypted("t1".to_string(), "v1".to_string()),
            EntryTag::Plaintext("t2".to_string(), "v2".to_string()),
        ],
    )];

    let mut conn = db.session(None, false).expect(ERR_SESSION);
    for upd in test_rows.iter() {
        conn.update(
            EntryKind::Item,
            EntryOperation::Insert,
            &upd.category,
            &upd.name,
            Some(&upd.value),
            Some(upd.tags.as_slice()),
            None,
        )
        .await
        .expect(ERR_INSERT);
    }
    drop(conn);

    let copy = db.create_profile(None).await.expect(ERR_PROFILE);
    let mut copy_conn = db.session(Some(copy.clone()), true).expect(ERR_SESSION);
    let records = db
        .scan(
            None,
            Some(EntryKind::Item),
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .await
        .expect(ERR_SCAN);
    copy_conn
        .import_scan(records)
        .await
        .expect("Error importing records");
    copy_conn.close(true).await.expect(ERR_COMMIT);

    let mut scan = db
        .scan(
            Some(copy),
            Some(EntryKind::Item),
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .await
        .expect(ERR_SCAN);

    let rows = scan.fetch_next().await.expect(ERR_SCAN_NEXT);
    assert_eq!(rows, Some(test_rows));
    let rows = scan.fetch_next().await.expect(ERR_SCAN_NEXT);
    assert_eq!(rows, None);
}
