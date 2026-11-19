use std::{fs::OpenOptions, path::Path};

use anyhow::{bail, Context, Result};
use askar_storage::{
    inspect::{self, InspectedItem, InspectionKey, Inspector, RawItem, RawProfile},
    PassKey,
};
use sha2::{Digest, Sha256};
use sqlx::{sqlite::SqliteConnectOptions, Connection, SqliteConnection};

pub mod agent;
pub mod apply;
pub mod changes;
pub mod commands;
pub mod describe;
pub mod mcp;
pub mod redact;
pub mod source;
pub mod sql;
pub mod ui;

/// Export a store to a plaintext, editable SQLite file.
pub async fn export(
    uri: &str,
    out: &Path,
    include_kms: bool,
    pass_key_env: Option<&str>,
) -> Result<()> {
    if !uri.starts_with("sqlite:")
        && !uri.starts_with("postgres:")
        && !uri.starts_with("postgresql:")
    {
        bail!("Expected an Askar sqlite: or postgres: URI");
    }
    eprintln!(
        "WARNING: {} will contain decrypted data. Restrict access and delete it after use.",
        out.display()
    );
    let mut target = create_target(out).await?;
    let result: Result<String> = if uri.starts_with("sqlite:") {
        let mut source = inspect::sqlite::open(uri).await?;
        let key_reference = inspect::sqlite::key_reference(&mut source).await?;
        let pass_key = read_pass_key(&key_reference, pass_key_env)?;
        let key = InspectionKey::resolve(&key_reference, pass_key)?;
        let profiles = inspect::sqlite::profiles(&mut source).await?;
        let fingerprint = fingerprint(&key_reference, &profiles);
        for profile in profiles {
            let inspector = prepare_profile(&mut target, &profile, &key).await?;
            if let Some(inspector) = inspector {
                let mut after_id = 0;
                loop {
                    let page =
                        inspect::sqlite::page(&mut source, profile.id, after_id, 500).await?;
                    if page.is_empty() {
                        break;
                    }
                    after_id = page.last().unwrap().id;
                    write_page(&mut target, profile.id, &inspector, page, include_kms).await?;
                }
            }
        }
        Ok(fingerprint)
    } else {
        let mut source = inspect::postgres::open(uri).await?;
        let key_reference = inspect::postgres::key_reference(&mut source).await?;
        let pass_key = read_pass_key(&key_reference, pass_key_env)?;
        let key = InspectionKey::resolve(&key_reference, pass_key)?;
        let profiles = inspect::postgres::profiles(&mut source).await?;
        let fingerprint = fingerprint(&key_reference, &profiles);
        for profile in profiles {
            let inspector = prepare_profile(&mut target, &profile, &key).await?;
            if let Some(inspector) = inspector {
                let mut after_id = 0;
                loop {
                    let page =
                        inspect::postgres::page(&mut source, profile.id, after_id, 500).await?;
                    if page.is_empty() {
                        break;
                    }
                    after_id = page.last().unwrap().id;
                    write_page(&mut target, profile.id, &inspector, page, include_kms).await?;
                }
            }
        }
        Ok(fingerprint)
    };
    let result = match result {
        Ok(fingerprint) => finish_export(&mut target, &fingerprint).await,
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        eprintln!("Incomplete export at {}: {error:#}", out.display());
        return Err(error);
    }
    eprintln!("Export complete: {}", out.display());
    Ok(())
}

/// Read the store pass key from the named variable, `ASKAR_EXPLORER_PASS_KEY`, the file named
/// by `ASKAR_EXPLORER_PASS_KEY_FILE` (for container secrets), or a prompt.
pub fn read_pass_key(key_reference: &str, env_name: Option<&str>) -> Result<PassKey<'static>> {
    if key_reference == "none" {
        return Ok(PassKey::empty());
    }
    let pass_key = match env_name {
        Some(name) => {
            std::env::var(name).with_context(|| format!("Missing environment variable {name}"))?
        }
        None => match std::env::var("ASKAR_EXPLORER_PASS_KEY") {
            Ok(pass_key) => pass_key,
            Err(std::env::VarError::NotPresent) => {
                match std::env::var("ASKAR_EXPLORER_PASS_KEY_FILE") {
                    Ok(path) => {
                        let text = std::fs::read_to_string(&path)
                            .with_context(|| format!("Cannot read the pass key file {path}"))?;
                        text.trim_end_matches(['\r', '\n']).to_owned()
                    }
                    Err(std::env::VarError::NotPresent) => {
                        // Ask once per process: a change set reads, then writes, the same store.
                        static PROMPTED: std::sync::Mutex<Option<String>> =
                            std::sync::Mutex::new(None);
                        let mut cached = PROMPTED.lock().unwrap_or_else(|e| e.into_inner());
                        match cached.as_ref() {
                            Some(pass_key) => pass_key.clone(),
                            None => {
                                let pass_key = rpassword::prompt_password("Askar pass key: ")?;
                                *cached = Some(pass_key.clone());
                                pass_key
                            }
                        }
                    }
                    Err(error) => {
                        return Err(error).context("Invalid ASKAR_EXPLORER_PASS_KEY_FILE")
                    }
                }
            }
            Err(error) => return Err(error).context("Invalid ASKAR_EXPLORER_PASS_KEY"),
        },
    };
    Ok(PassKey::from(pass_key))
}

/// Identify a store by its key method and wrapped profile keys.
pub fn fingerprint(key_reference: &str, profiles: &[RawProfile]) -> String {
    let mut hash = Sha256::new();
    hash.update(key_reference.as_bytes());
    for profile in profiles {
        hash.update(profile.id.to_be_bytes());
        hash.update(profile.name.as_bytes());
        hash.update(profile.profile_key.as_deref().unwrap_or_default());
    }
    hex::encode(hash.finalize())
}

async fn finish_export(target: &mut SqliteConnection, fingerprint: &str) -> Result<()> {
    sqlx::query(
        "CREATE TABLE original_profiles AS SELECT id, name FROM profiles;
                 CREATE TABLE original_items AS SELECT * FROM items;
                 CREATE TABLE original_item_tags AS SELECT * FROM item_tags;
                 INSERT INTO export_meta (name, value) VALUES ('version', '1');",
    )
    .execute(&mut *target)
    .await?;
    sqlx::query("INSERT INTO export_meta (name, value) VALUES ('fingerprint', ?)")
        .bind(fingerprint)
        .execute(target)
        .await?;
    Ok(())
}

async fn create_target(path: &Path) -> Result<SqliteConnection> {
    let mut create = OpenOptions::new();
    create.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        create.mode(0o600);
    }
    create
        .open(path)
        .with_context(|| format!("Cannot create {}", path.display()))?;
    let options = SqliteConnectOptions::new()
        .filename(path)
        .foreign_keys(true);
    let mut connection = SqliteConnection::connect_with(&options).await?;
    sqlx::query(
        "CREATE TABLE profiles (id INTEGER PRIMARY KEY, name TEXT NOT NULL, key_error TEXT);
                 CREATE TABLE items (row_id INTEGER PRIMARY KEY, profile_id INTEGER NOT NULL, id INTEGER,
                     kind INTEGER NOT NULL DEFAULT 2,
           category TEXT, name TEXT, value BLOB, expiry TEXT,
                     category_error TEXT, name_error TEXT, value_error TEXT);
                 CREATE TABLE item_tags (row_id INTEGER PRIMARY KEY,
                     item_row_id INTEGER NOT NULL REFERENCES items(row_id) ON DELETE CASCADE,
                     name TEXT, value TEXT, plaintext INTEGER NOT NULL DEFAULT 0, error TEXT);
                 CREATE TABLE export_meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE VIEW readable_items AS SELECT row_id, profile_id, id, kind, category, name,
           CAST(value AS TEXT) AS value_text, expiry FROM items;",
    )
    .execute(&mut connection)
    .await?;
    Ok(connection)
}

async fn prepare_profile(
    target: &mut SqliteConnection,
    profile: &RawProfile,
    key: &InspectionKey,
) -> Result<Option<Inspector>> {
    let inspector = profile
        .profile_key
        .as_ref()
        .map(|wrapped| key.unlock(wrapped.clone()));
    let (inspector, error) = match inspector {
        Some(Ok(inspector)) => (Some(inspector), None),
        Some(Err(error)) => (None, Some(error.to_string())),
        None => (None, Some("Missing profile key".to_owned())),
    };
    sqlx::query("INSERT INTO profiles (id, name, key_error) VALUES (?, ?, ?)")
        .bind(profile.id)
        .bind(&profile.name)
        .bind(&error)
        .execute(target)
        .await?;
    if let Some(error) = error {
        bail!("Cannot unlock profile {}: {error}", profile.name);
    }
    Ok(inspector)
}

async fn write_page(
    target: &mut SqliteConnection,
    profile_id: i64,
    inspector: &Inspector,
    page: Vec<RawItem>,
    include_kms: bool,
) -> Result<()> {
    sqlx::query("BEGIN").execute(&mut *target).await?;
    for raw in page {
        if raw.kind == 1 && !include_kms {
            continue;
        }
        let item = inspector.decrypt(raw);
        write_item(&mut *target, profile_id, item).await?;
    }
    sqlx::query("COMMIT").execute(target).await?;
    Ok(())
}

async fn write_item(
    target: &mut SqliteConnection,
    profile_id: i64,
    item: InspectedItem,
) -> Result<()> {
    let (category, category_error) = split_result(item.category);
    let (name, name_error) = split_result(item.name);
    let (value, value_error) = split_result(item.value);
    let item_row_id = sqlx::query(
        "INSERT INTO items (profile_id, id, kind, category, name, value, expiry,
          category_error, name_error, value_error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(profile_id)
    .bind(item.id)
    .bind(item.kind)
    .bind(category)
    .bind(name)
    .bind(value.map(|value| value.into_vec()))
    .bind(item.expiry.map(|expiry| expiry.to_string()))
    .bind(category_error)
    .bind(name_error)
    .bind(value_error)
    .execute(&mut *target)
    .await?
    .last_insert_rowid();
    for tag in item.tags {
        let (tag, error) = split_result(tag);
        let (name, value, plaintext) = match tag {
            Some(askar_storage::entry::EntryTag::Plaintext(name, value)) => {
                (Some(name), Some(value), Some(true))
            }
            Some(askar_storage::entry::EntryTag::Encrypted(name, value)) => {
                (Some(name), Some(value), Some(false))
            }
            None => (None, None, None),
        };
        sqlx::query(
            "INSERT INTO item_tags (item_row_id, name, value, plaintext, error)
                            VALUES (?, ?, ?, ?, ?)",
        )
        .bind(item_row_id)
        .bind(name)
        .bind(value)
        .bind(plaintext)
        .bind(error)
        .execute(&mut *target)
        .await?;
    }
    Ok(())
}

fn split_result<T>(result: Result<T, askar_storage::Error>) -> (Option<T>, Option<String>) {
    match result {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use askar_storage::{
        entry::{EntryKind, EntryOperation, EntryTag},
        sqlite::SqliteStoreOptions,
        Backend, BackendSession, ManageBackend, StoreKeyMethod,
    };
    use sqlx::Row;

    #[tokio::test]
    async fn exports_expired_entries_and_both_tag_types() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("source.db");
        let destination = directory.path().join("export.db");
        let backend = SqliteStoreOptions::new(source.to_str().unwrap())?
            .provision_backend(
                StoreKeyMethod::Unprotected,
                PassKey::empty(),
                Some("main".to_owned()),
                false,
            )
            .await?;
        let mut session = backend.session(None, false)?;
        let value = askar_storage::crypto::buffer::SecretBytes::from(b"{\"ok\":true}".as_slice());
        let tags = [
            EntryTag::Plaintext("status".to_owned(), "active".to_owned()),
            EntryTag::Encrypted("private".to_owned(), "secret".to_owned()),
        ];
        session
            .update(
                EntryKind::Item,
                EntryOperation::Insert,
                "records",
                "first",
                Some(&value),
                Some(&tags),
                Some(-1000),
            )
            .await?;
        session
            .update(
                EntryKind::Kms,
                EntryOperation::Insert,
                "keys",
                "secret",
                Some(&value),
                None,
                None,
            )
            .await?;
        session.close(false).await?;
        backend.close().await?;

        export(
            &format!("sqlite://{}", source.display()),
            &destination,
            false,
            None,
        )
        .await?;
        let mut output =
            SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&destination))
                .await?;
        let item = sqlx::query("SELECT category, name, value, expiry, value_error FROM items")
            .fetch_one(&mut output)
            .await?;
        assert_eq!(item.try_get::<String, _>("category")?, "records");
        assert_eq!(item.try_get::<String, _>("name")?, "first");
        assert_eq!(item.try_get::<Vec<u8>, _>("value")?, b"{\"ok\":true}");
        assert!(item.try_get::<Option<String>, _>("expiry")?.is_some());
        assert!(item.try_get::<Option<String>, _>("value_error")?.is_none());
        let tags = sqlx::query("SELECT name, value FROM item_tags ORDER BY row_id")
            .fetch_all(&mut output)
            .await?;
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].try_get::<String, _>("value")?, "active");
        assert_eq!(tags[1].try_get::<String, _>("value")?, "secret");

        let mut source_connection =
            SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&source)).await?;
        sqlx::query("UPDATE items SET value = X'00' WHERE kind = 2")
            .execute(&mut source_connection)
            .await?;
        source_connection.close().await?;
        let damaged_export = directory.path().join("damaged.db");
        export(
            &format!("sqlite://{}", source.display()),
            &damaged_export,
            true,
            None,
        )
        .await?;
        let mut damaged =
            SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&damaged_export))
                .await?;
        let rows = sqlx::query("SELECT kind, category, value_error FROM items ORDER BY kind")
            .fetch_all(&mut damaged)
            .await?;
        assert_eq!(rows.len(), 2);
        assert!(rows[0]
            .try_get::<Option<String>, _>("value_error")?
            .is_none());
        assert_eq!(rows[1].try_get::<String, _>("category")?, "records");
        assert!(rows[1]
            .try_get::<Option<String>, _>("value_error")?
            .is_some());
        Ok(())
    }

    #[tokio::test]
    async fn apply_round_trip_and_reject_stale_export() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("source.db");
        let edits = directory.path().join("edits.db");
        let uri = format!("sqlite://{}", source.display());
        let store = SqliteStoreOptions::new(source.to_str().unwrap())?
            .provision_backend(
                StoreKeyMethod::Unprotected,
                PassKey::empty(),
                Some("main".to_owned()),
                false,
            )
            .await?;
        let mut session = store.session(None, false)?;
        for name in ["update", "remove"] {
            let value = askar_storage::crypto::buffer::SecretBytes::from(name.as_bytes());
            session
                .update(
                    EntryKind::Item,
                    EntryOperation::Insert,
                    "records",
                    name,
                    Some(&value),
                    Some(&[EntryTag::Encrypted("state".into(), "old".into())]),
                    None,
                )
                .await?;
        }
        session.close(false).await?;
        store.close().await?;
        export(&uri, &edits, false, None).await?;

        let mut db =
            SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&edits)).await?;
        for query in [
            "UPDATE items SET value = 'changed' WHERE name = 'update'",
            "UPDATE item_tags SET value = 'new' WHERE item_row_id = (SELECT row_id FROM items WHERE name = 'update')",
            "DELETE FROM item_tags WHERE item_row_id = (SELECT row_id FROM items WHERE name = 'remove')",
            "DELETE FROM items WHERE name = 'remove'",
            "INSERT INTO items (profile_id, category, name, value) SELECT id, 'records', 'added', 'fresh' FROM profiles",
            "INSERT INTO item_tags (item_row_id, name, value, plaintext) SELECT row_id, 'state', 'created', 1 FROM items WHERE name = 'added'",
        ] {
            sqlx::query(query).execute(&mut db).await?;
        }
        db.close().await?;
        apply::run(&uri, &edits, false, None).await?;

        let store = uri
            .as_str()
            .open_backend(None, PassKey::empty(), None)
            .await?;
        let mut session = store.session(None, false)?;
        assert_eq!(
            session
                .fetch(EntryKind::Item, "records", "update", false)
                .await?
                .unwrap()
                .value
                .as_ref(),
            b"update"
        );
        session.close(false).await?;
        store.close().await?;

        let store = uri
            .as_str()
            .open_backend(None, PassKey::empty(), None)
            .await?;
        let mut session = store.session(None, false)?;
        session
            .update(
                EntryKind::Item,
                EntryOperation::Replace,
                "records",
                "update",
                Some(b"concurrent"),
                None,
                None,
            )
            .await?;
        session.close(false).await?;
        store.close().await?;
        assert!(apply::run(&uri, &edits, true, None).await.is_err());
        let store = uri
            .as_str()
            .open_backend(None, PassKey::empty(), None)
            .await?;
        let mut session = store.session(None, false)?;
        assert!(session
            .fetch(EntryKind::Item, "records", "remove", false)
            .await?
            .is_some());
        session
            .update(
                EntryKind::Item,
                EntryOperation::Replace,
                "records",
                "update",
                Some(b"update"),
                Some(&[EntryTag::Encrypted("state".into(), "old".into())]),
                None,
            )
            .await?;
        session.close(false).await?;
        store.close().await?;

        apply::run(&uri, &edits, true, None).await?;
        let store = uri
            .as_str()
            .open_backend(None, PassKey::empty(), None)
            .await?;
        let mut session = store.session(None, false)?;
        let updated = session
            .fetch(EntryKind::Item, "records", "update", false)
            .await?
            .unwrap();
        assert_eq!(updated.value.as_ref(), b"changed");
        assert_eq!(
            updated.tags,
            vec![EntryTag::Encrypted("state".into(), "new".into())]
        );
        assert!(session
            .fetch(EntryKind::Item, "records", "remove", false)
            .await?
            .is_none());
        let added = session
            .fetch(EntryKind::Item, "records", "added", false)
            .await?
            .unwrap();
        assert_eq!(added.value.as_ref(), b"fresh");
        assert_eq!(
            added.tags,
            vec![EntryTag::Plaintext("state".into(), "created".into())]
        );
        session.close(false).await?;
        store.close().await?;
        assert!(apply::run(&uri, &edits, true, None).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn postgres_export_and_apply_when_configured() -> Result<()> {
        let Ok(base_uri) = std::env::var("POSTGRES_URL") else {
            return Ok(());
        };
        let schema = format!(
            "explorer_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_millis()
        );
        let uri = format!("{base_uri}?schema={schema}");
        let directory = tempfile::tempdir()?;
        let edits = directory.path().join("postgres.db");
        let store = askar_storage::postgres::PostgresStoreOptions::new(uri.as_str())?
            .provision(
                StoreKeyMethod::Unprotected,
                PassKey::empty(),
                Some("main".into()),
                false,
            )
            .await?;
        let mut session = store.session(None, false)?;
        session
            .update(
                EntryKind::Item,
                EntryOperation::Insert,
                "records",
                "original",
                Some(b"before"),
                None,
                None,
            )
            .await?;
        session.close(false).await?;
        store.close().await?;
        let result = async {
            export(&uri, &edits, false, None).await?;
            let mut db =
                SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&edits))
                    .await?;
            sqlx::query("UPDATE items SET value = 'after' WHERE name = 'original'")
                .execute(&mut db)
                .await?;
            sqlx::query(
                "INSERT INTO items (profile_id, category, name, value)
                SELECT id, 'records', 'added', 'new' FROM profiles",
            )
            .execute(&mut db)
            .await?;
            db.close().await?;
            apply::run(&uri, &edits, true, None).await?;
            let store = uri
                .as_str()
                .open_backend(None, PassKey::empty(), None)
                .await?;
            let mut session = store.session(None, false)?;
            assert_eq!(
                session
                    .fetch(EntryKind::Item, "records", "original", false)
                    .await?
                    .unwrap()
                    .value
                    .as_ref(),
                b"after"
            );
            assert_eq!(
                session
                    .fetch(EntryKind::Item, "records", "added", false)
                    .await?
                    .unwrap()
                    .value
                    .as_ref(),
                b"new"
            );
            session.close(false).await?;
            store.close().await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        let mut connection = sqlx::PgConnection::connect(&base_uri).await?;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA \"{schema}\" CASCADE"
        )))
        .execute(&mut connection)
        .await?;
        connection.close().await?;
        result
    }
}
