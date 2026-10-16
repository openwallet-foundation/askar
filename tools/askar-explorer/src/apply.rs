use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use askar_storage::{
    any::{AnyBackend, AnyBackendSession},
    entry::{EntryKind, EntryOperation, EntryTag},
    inspect::{self, RawProfile},
    Backend, BackendSession, ManageBackend,
};
use chrono::NaiveDateTime;
use sqlx::{sqlite::SqliteConnectOptions, Connection, Row, SqliteConnection};

use super::{fingerprint, read_pass_key};

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Record {
    pub(crate) profile_id: i64,
    pub(crate) kind: i64,
    pub(crate) category: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) value: Option<Vec<u8>>,
    pub(crate) expiry: Option<String>,
    pub(crate) damaged: bool,
    pub(crate) tags: Vec<Tag>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Tag {
    pub(crate) name: Option<String>,
    pub(crate) value: Option<String>,
    pub(crate) plaintext: bool,
    pub(crate) error: Option<String>,
}

#[derive(Debug)]
pub(crate) enum Change {
    Remove(Record),
    Replace(Record, Record),
    Insert(Record),
}

impl Change {
    pub(crate) fn record(&self) -> &Record {
        match self {
            Self::Remove(record) | Self::Insert(record) | Self::Replace(_, record) => record,
        }
    }

    fn rank(&self) -> u8 {
        match self {
            Self::Remove(_) => 0,
            Self::Replace(..) => 1,
            Self::Insert(_) => 2,
        }
    }

    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Remove(_) => "remove",
            Self::Replace(..) => "replace",
            Self::Insert(_) => "insert",
        }
    }
}

impl Record {
    pub(crate) fn category(&self) -> &str {
        self.category.as_deref().unwrap_or_default()
    }

    pub(crate) fn name(&self) -> &str {
        self.name.as_deref().unwrap_or_default()
    }

    pub(crate) fn kind(&self) -> Result<EntryKind> {
        ensure!(
            self.kind == 1 || self.kind == 2,
            "Invalid entry kind {}",
            self.kind
        );
        Ok(EntryKind::try_from(self.kind as usize)?)
    }

    pub(crate) fn entry_tags(&self) -> Vec<EntryTag> {
        self.tags
            .iter()
            .map(|tag| {
                let name = tag.name.clone().unwrap_or_default();
                let value = tag.value.clone().unwrap_or_default();
                if tag.plaintext {
                    EntryTag::Plaintext(name, value)
                } else {
                    EntryTag::Encrypted(name, value)
                }
            })
            .collect()
    }

    fn expiry_ms(&self) -> Result<Option<i64>> {
        self.expiry
            .as_deref()
            .map(|expiry| {
                let at = NaiveDateTime::parse_from_str(expiry, "%Y-%m-%d %H:%M:%S%.f")
                    .with_context(|| {
                        format!("Expected UTC expiry YYYY-MM-DD HH:MM:SS, got {expiry:?}")
                    })?;
                Ok((at - chrono::Utc::now().naive_utc()).num_milliseconds())
            })
            .transpose()
    }

    pub(crate) fn describe(&self, profiles: &HashMap<i64, String>) -> String {
        format!(
            "profile={} kind={} category={:?} name={:?}",
            profiles
                .get(&self.profile_id)
                .map(String::as_str)
                .unwrap_or("?"),
            self.kind,
            self.category(),
            self.name()
        )
    }

    fn validate(&self, row_id: i64, profiles: &HashMap<i64, String>) -> Result<()> {
        ensure!(!self.damaged, "Row {row_id} has decryption errors");
        ensure!(
            profiles.contains_key(&self.profile_id),
            "Row {row_id} has an unknown profile"
        );
        self.kind()?;
        ensure!(
            self.category.is_some() && self.name.is_some() && self.value.is_some(),
            "Row {row_id} requires category, name, and value"
        );
        ensure!(
            self.tags
                .iter()
                .all(|tag| tag.name.is_some() && tag.value.is_some()),
            "Row {row_id} has an incomplete tag"
        );
        self.expiry_ms()?;
        Ok(())
    }
}

async fn read_records(
    db: &mut SqliteConnection,
    items: &str,
    tags: &str,
) -> Result<BTreeMap<i64, Record>> {
    let sql = format!("SELECT row_id, profile_id, kind, category, name, CAST(value AS BLOB) AS value,
        expiry, (category_error IS NOT NULL OR name_error IS NOT NULL OR value_error IS NOT NULL) AS damaged
        FROM {items}");
    let mut records = BTreeMap::new();
    for row in sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
        .fetch_all(&mut *db)
        .await?
    {
        records.insert(
            row.try_get::<i64, _>("row_id")?,
            Record {
                profile_id: row.try_get("profile_id")?,
                kind: row.try_get("kind")?,
                category: row.try_get("category")?,
                name: row.try_get("name")?,
                value: row.try_get("value")?,
                expiry: row.try_get("expiry")?,
                damaged: row.try_get::<i64, _>("damaged")? != 0,
                tags: Vec::new(),
            },
        );
    }
    let sql = format!("SELECT item_row_id, name, value, plaintext, error FROM {tags}");
    for row in sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
        .fetch_all(&mut *db)
        .await?
    {
        let item_row_id: i64 = row.try_get("item_row_id")?;
        let record = records
            .get_mut(&item_row_id)
            .ok_or_else(|| anyhow!("Orphaned tag in {tags} for item row {item_row_id}"))?;
        record.tags.push(Tag {
            name: row.try_get("name")?,
            value: row.try_get("value")?,
            plaintext: row.try_get::<i64, _>("plaintext")? != 0,
            error: row.try_get("error")?,
        });
    }
    for record in records.values_mut() {
        record.tags.sort();
        record.damaged |= record.tags.iter().any(|tag| tag.error.is_some());
    }
    Ok(records)
}

fn plan(
    original: &BTreeMap<i64, Record>,
    current: &BTreeMap<i64, Record>,
    profiles: &HashMap<i64, String>,
) -> Result<Vec<Change>> {
    let mut changes = Vec::new();
    for (row_id, old) in original {
        match current.get(row_id) {
            Some(new) if new == old => {}
            changed => {
                ensure!(
                    !old.damaged,
                    "Row {row_id} failed to decrypt and cannot be modified"
                );
                match changed {
                    None => changes.push(Change::Remove(old.clone())),
                    Some(new) => {
                        new.validate(*row_id, profiles)?;
                        ensure!(
                            old.profile_id == new.profile_id,
                            "Row {row_id} cannot change profile; remove it and insert a new row"
                        );
                        if (old.kind, &old.category, &old.name)
                            == (new.kind, &new.category, &new.name)
                        {
                            changes.push(Change::Replace(old.clone(), new.clone()));
                        } else {
                            changes.push(Change::Remove(old.clone()));
                            changes.push(Change::Insert(new.clone()));
                        }
                    }
                }
            }
        }
    }
    for (row_id, new) in current {
        if !original.contains_key(row_id) {
            new.validate(*row_id, profiles)?;
            changes.push(Change::Insert(new.clone()));
        }
    }
    changes.sort_by_key(Change::rank);
    Ok(changes)
}

pub(crate) async fn source_fingerprint(uri: &str) -> Result<(String, String)> {
    if uri.starts_with("sqlite:") {
        let mut db = inspect::sqlite::open(uri).await?;
        let key = inspect::sqlite::key_reference(&mut db).await?;
        let profiles: Vec<RawProfile> = inspect::sqlite::profiles(&mut db).await?;
        Ok((key.clone(), fingerprint(&key, &profiles)))
    } else {
        let mut db = inspect::postgres::open(uri).await?;
        let key = inspect::postgres::key_reference(&mut db).await?;
        let profiles: Vec<RawProfile> = inspect::postgres::profiles(&mut db).await?;
        Ok((key.clone(), fingerprint(&key, &profiles)))
    }
}

/// Show the changes made to an export and, with `commit`, write them to the store.
pub async fn run(uri: &str, edits: &Path, commit: bool, pass_key_env: Option<&str>) -> Result<()> {
    ensure!(
        uri.starts_with("sqlite:")
            || uri.starts_with("postgres:")
            || uri.starts_with("postgresql:"),
        "Expected an Askar sqlite: or postgres: URI"
    );
    let mut db = SqliteConnection::connect_with(
        &SqliteConnectOptions::new().filename(edits).read_only(true),
    )
    .await
    .with_context(|| format!("Cannot open {}", edits.display()))?;
    let version: String =
        sqlx::query_scalar("SELECT value FROM export_meta WHERE name = 'version'")
            .fetch_one(&mut db)
            .await
            .context("Not a completed explorer export")?;
    ensure!(version == "1", "Unsupported explorer export version");
    let fingerprint: String =
        sqlx::query_scalar("SELECT value FROM export_meta WHERE name = 'fingerprint'")
            .fetch_one(&mut db)
            .await?;
    let profiles: HashMap<i64, String> = sqlx::query_as("SELECT id, name FROM profiles")
        .fetch_all(&mut db)
        .await?
        .into_iter()
        .collect();
    let original_profiles: HashMap<i64, String> =
        sqlx::query_as("SELECT id, name FROM original_profiles")
            .fetch_all(&mut db)
            .await?
            .into_iter()
            .collect();
    ensure!(
        profiles == original_profiles,
        "Export profile list was edited; re-export before applying"
    );
    let original = read_records(&mut db, "original_items", "original_item_tags").await?;
    let current = read_records(&mut db, "items", "item_tags").await?;
    db.close().await?;
    let changes = plan(&original, &current, &profiles)?;
    if changes.is_empty() {
        println!("No changes.");
        return Ok(());
    }
    for change in &changes {
        println!(
            "{:<8}{}",
            change.label(),
            change.record().describe(&profiles)
        );
    }
    if !commit {
        println!(
            "Dry run: re-run with --commit --confirm-backup to apply {} change(s).",
            changes.len()
        );
        return Ok(());
    }
    let (key_reference, actual_fingerprint) = source_fingerprint(uri).await?;
    ensure!(
        fingerprint == actual_fingerprint,
        "Source store or profiles changed since export"
    );
    let pass_key = read_pass_key(&key_reference, pass_key_env)?;
    let store = uri.open_backend(None, pass_key, None).await?;
    write_all(&store, &changes, &profiles).await?;
    store.close().await?;
    println!(
        "Applied {} change(s). Re-export before further edits.",
        changes.len()
    );
    Ok(())
}

/// Write changes through Askar, one transaction per profile, checking each existing entry
/// still matches what was read before it is replaced or removed.
pub(crate) async fn write_all(
    store: &AnyBackend,
    changes: &[Change],
    profiles: &HashMap<i64, String>,
) -> Result<()> {
    let mut ordered: Vec<&Change> = changes.iter().collect();
    ordered.sort_by_key(|change| change.rank());
    let mut groups: BTreeMap<i64, Vec<&Change>> = BTreeMap::new();
    for change in ordered {
        groups
            .entry(change.record().profile_id)
            .or_default()
            .push(change);
    }
    let mut committed = Vec::new();
    for (profile_id, changes) in groups {
        let profile = profiles.get(&profile_id).context("Unknown profile")?;
        let mut session = store.session(Some(profile.clone()), true)?;
        let result = write_changes(&mut session, &changes, profiles).await;
        match result {
            Ok(()) => {
                session.close(true).await?;
                committed.push(profile.clone());
            }
            Err(error) => {
                session.close(false).await.ok();
                bail!(
                    "Profile {profile} rolled back: {error:#}. Profiles already committed: {:?}",
                    committed
                );
            }
        }
    }
    Ok(())
}

async fn write_changes(
    session: &mut AnyBackendSession,
    changes: &[&Change],
    profiles: &HashMap<i64, String>,
) -> Result<()> {
    for change in changes {
        match change {
            Change::Remove(old) => {
                check_existing(session, old, profiles).await?;
                session
                    .update(
                        old.kind()?,
                        EntryOperation::Remove,
                        old.category(),
                        old.name(),
                        None,
                        None,
                        None,
                    )
                    .await?;
            }
            Change::Replace(old, new) => {
                check_existing(session, old, profiles).await?;
                write_entry(session, new, EntryOperation::Replace).await?;
            }
            Change::Insert(new) => write_entry(session, new, EntryOperation::Insert).await?,
        }
    }
    Ok(())
}

async fn check_existing(
    session: &mut AnyBackendSession,
    old: &Record,
    profiles: &HashMap<i64, String>,
) -> Result<()> {
    let current = session
        .fetch(old.kind()?, old.category(), old.name(), true)
        .await?
        .ok_or_else(|| anyhow!("{} is missing or expired", old.describe(profiles)))?;
    let mut current_tags = current.tags;
    current_tags.sort();
    let mut original_tags = old.entry_tags();
    original_tags.sort();
    ensure!(
        current.value.as_ref() == old.value.as_deref().unwrap_or_default()
            && current_tags == original_tags,
        "{} changed since export; re-export before applying",
        old.describe(profiles)
    );
    Ok(())
}

async fn write_entry(
    session: &mut AnyBackendSession,
    entry: &Record,
    operation: EntryOperation,
) -> Result<()> {
    let tags = entry.entry_tags();
    session
        .update(
            entry.kind()?,
            operation,
            entry.category(),
            entry.name(),
            entry.value.as_deref(),
            Some(tags.as_slice()),
            entry.expiry_ms()?,
        )
        .await?;
    Ok(())
}
