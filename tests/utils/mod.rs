use aries_askar::{
    verify_signature, wql, Backend, Entry, EntryTag, KeyAlg, Result as KvResult, Store,
};

pub async fn db_fetch_fail<DB: Backend>(db: &Store<DB>) -> KvResult<()> {
    let mut conn = db.session(None).await?;
    let result = conn.fetch("cat".to_string(), "name".to_string()).await?;
    assert!(result.is_none());
    Ok(())
}

pub async fn db_add_duplicate_fail<DB: Backend>(db: &Store<DB>) -> KvResult<()> {
    let test_row = Entry {
        category: "cat".to_string(),
        name: "name".to_string(),
        value: b"value".to_vec(),
        tags: None,
    };

    let mut conn = db.session(None).await?;

    conn.insert(
        test_row.category.clone(),
        test_row.name.clone(),
        test_row.value.clone(),
        test_row.tags.clone(),
    )
    .await?;

    assert_eq!(
        conn.insert(
            test_row.category.clone(),
            test_row.name.clone(),
            test_row.value.clone(),
            test_row.tags.clone(),
        )
        .await
        .is_err(),
        true
    );
    Ok(())
}

pub async fn db_add_fetch<DB: Backend>(db: &Store<DB>) -> KvResult<()> {
    let test_row = Entry {
        category: "cat".to_string(),
        name: "name".to_string(),
        value: b"value".to_vec(),
        tags: Some(vec![
            EntryTag::Encrypted("t1".to_string(), "v1".to_string()),
            EntryTag::Plaintext("t2".to_string(), "v2".to_string()),
        ]),
    };

    let mut conn = db.session(None).await?;

    conn.insert(
        test_row.category.clone(),
        test_row.name.clone(),
        test_row.value.clone(),
        test_row.tags.clone(),
    )
    .await?;

    let row = conn
        .fetch(test_row.category.clone(), test_row.name.clone())
        .await?;

    assert_eq!(row.is_some(), true);
    let found = row.unwrap();
    assert_eq!(found, test_row);

    Ok(())
}

pub async fn db_count<DB: Backend>(db: &Store<DB>) -> KvResult<()> {
    let category = "cat".to_string();
    let test_rows = vec![Entry {
        category: category.clone(),
        name: "name".to_string(),
        value: b"value".to_vec(),
        tags: None,
    }];

    let mut conn = db.session(None).await?;

    for upd in test_rows.iter() {
        conn.insert(
            upd.category.clone(),
            upd.name.clone(),
            upd.value.clone(),
            upd.tags.clone(),
        )
        .await?;
    }

    let tag_filter = None;
    let count = conn.count(category.clone(), tag_filter).await?;
    assert_eq!(count, 1);

    let tag_filter = Some(wql::Query::Eq("sometag".to_string(), "someval".to_string()));
    let count = conn.count(category.clone(), tag_filter).await?;
    assert_eq!(count, 0);

    Ok(())
}

pub async fn db_scan<DB: Backend>(db: &Store<DB>) -> KvResult<()> {
    let category = "cat".to_string();
    let test_rows = vec![Entry {
        category: category.clone(),
        name: "name".to_string(),
        value: b"value".to_vec(),
        tags: None,
    }];

    let mut conn = db.session(None).await?;

    for upd in test_rows.iter() {
        conn.insert(
            upd.category.clone(),
            upd.name.clone(),
            upd.value.clone(),
            upd.tags.clone(),
        )
        .await?;
    }
    drop(conn);

    let tag_filter = None;
    let offset = None;
    let limit = None;
    let mut scan = db
        .scan(None, category.clone(), tag_filter, offset, limit)
        .await?;
    let rows = scan.fetch_next().await?;
    assert_eq!(rows, Some(test_rows));
    let rows = scan.fetch_next().await?;
    assert_eq!(rows, None);

    let tag_filter = Some(wql::Query::Eq("sometag".to_string(), "someval".to_string()));
    let mut scan = db
        .scan(None, category.clone(), tag_filter, offset, limit)
        .await?;
    let rows = scan.fetch_next().await?;
    assert_eq!(rows, None);

    Ok(())
}

pub async fn db_keypair_create_fetch<DB: Backend>(db: &Store<DB>) -> KvResult<()> {
    let mut conn = db.session(None).await?;

    let metadata = "meta".to_owned();
    let key_info = conn
        .create_keypair(KeyAlg::ED25519, Some(metadata.clone()), None, None)
        .await?;
    assert_eq!(key_info.params.metadata, Some(metadata));

    let found = conn
        .fetch_key(key_info.category.clone(), key_info.ident.clone())
        .await?;
    assert_eq!(Some(key_info), found);

    Ok(())
}

pub async fn db_keypair_sign_verify<DB: Backend>(db: &Store<DB>) -> KvResult<()> {
    let mut conn = db.session(None).await?;

    let key_info = conn
        .create_keypair(KeyAlg::ED25519, None, None, None)
        .await?;

    let message = b"message".to_vec();
    let sig = conn
        .sign_message(key_info.ident.clone(), message.clone())
        .await?;

    assert_eq!(
        verify_signature(&key_info.ident, &message, &sig).await?,
        true
    );

    assert_eq!(
        verify_signature(&key_info.ident, b"bad input", &sig).await?,
        false
    );

    assert_eq!(
        verify_signature(&key_info.ident, &message, b"bad sig").await?,
        false
    );

    assert_eq!(
        verify_signature("not a key", &message, &sig).await.is_err(),
        true
    );

    Ok(())
}

// pub async fn db_keypair_pack_unpack_anon<DB: Backend>(db: &Store<DB>) -> KvResult<()> {
//     let recip_key = db
//         .create_keypair(None, KeyAlg::ED25519, None, None, None)
//         .await?;

//     let msg = b"message".to_vec();

//     let packed = db
//         .pack_message(None, vec![recip_key.ident.clone()], None, msg.clone())
//         .await?;

//     let (unpacked, p_recip, p_send) = db.unpack_message(None, packed.clone()).await?;
//     assert_eq!(unpacked, msg);
//     assert_eq!(p_recip, recip_key.encoded_verkey().unwrap());
//     assert_eq!(p_send, None);

//     Ok(())
// }

// pub async fn db_keypair_pack_unpack_auth<DB: Backend>(db: &Store<DB>) -> KvResult<()> {
//     let sender_key = db
//         .create_keypair(None, KeyAlg::ED25519, None, None, None)
//         .await?;
//     let recip_key = db
//         .create_keypair(None, KeyAlg::ED25519, None, None, None)
//         .await?;

//     let msg = b"message".to_vec();

//     let packed = db
//         .pack_message(
//             None,
//             vec![recip_key.ident.clone()],
//             Some(sender_key.ident.clone()),
//             msg.clone(),
//         )
//         .await?;

//     let (unpacked, p_recip, p_send) = db.unpack_message(None, packed.clone()).await?;
//     assert_eq!(unpacked, msg);
//     assert_eq!(p_recip, recip_key.encoded_verkey().unwrap());
//     assert_eq!(p_send, Some(sender_key.encoded_verkey().unwrap()));

//     Ok(())
// }
