//! Live, read-only access to an Askar store with all profile keys unlocked.

use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use askar_storage::inspect::{
    self, ExpiryFilter, InspectedItem, InspectionKey, Inspector, RawFilter,
};
use askar_storage::PassKey;
use sqlx::{PgConnection, SqliteConnection};

use crate::read_pass_key;

enum Conn {
    Sqlite(SqliteConnection),
    Postgres(PgConnection),
}

macro_rules! on_conn {
    ($conn:expr, $reads:ident, $c:ident => $body:expr) => {
        match $conn {
            Conn::Sqlite($c) => {
                use askar_storage::inspect::sqlite as $reads;
                $body
            }
            Conn::Postgres($c) => {
                use askar_storage::inspect::postgres as $reads;
                $body
            }
        }
    };
}

/// A store profile; its key may have failed to unlock.
#[derive(Clone, Debug)]
pub struct Profile {
    /// Database row identifier.
    pub id: i64,
    /// Profile name.
    pub name: String,
    inspector: Result<Arc<Inspector>, String>,
}

impl Profile {
    /// Why the profile key could not be unlocked, if it could not.
    pub fn key_error(&self) -> Option<&str> {
        self.inspector.as_ref().err().map(String::as_str)
    }

    fn inspector(&self) -> Result<&Inspector> {
        self.inspector
            .as_deref()
            .map_err(|error| anyhow!("Cannot unlock profile {}: {error}", self.name))
    }
}

/// A tag equality condition.
#[derive(Clone, Debug)]
pub struct TagCondition {
    /// Tag name.
    pub name: String,
    /// Tag value to match exactly.
    pub value: String,
    /// Whether the tag is stored in plaintext.
    pub plaintext: bool,
}

impl TagCondition {
    /// Parse `name=value`.
    pub fn parse(spec: &str, plaintext: bool) -> Result<Self> {
        let (name, value) = spec
            .split_once('=')
            .filter(|(name, _)| !name.is_empty())
            .ok_or_else(|| anyhow!("Expected a tag as name=value, got {spec:?}"))?;
        Ok(Self {
            name: name.to_owned(),
            value: value.to_owned(),
            plaintext,
        })
    }
}

/// Equality conditions that the database can evaluate without decrypting values.
#[derive(Clone, Debug, Default)]
pub struct Query {
    /// Database row identifier.
    pub id: Option<i64>,
    /// Entry kind: 1 for key-manager entries, 2 for ordinary items.
    pub kind: Option<i64>,
    /// Exact category.
    pub category: Option<String>,
    /// Exact entry name.
    pub name: Option<String>,
    /// Tags that must all match.
    pub tags: Vec<TagCondition>,
    /// Expiry restriction.
    pub expiry: ExpiryFilter,
}

/// Row counts for one category of one profile.
#[derive(Debug)]
pub struct Stat {
    /// Profile name.
    pub profile: String,
    /// Entry kind: 1 for key-manager entries, 2 for ordinary items.
    pub kind: i64,
    /// Category, or a marker when it could not be decrypted.
    pub category: String,
    /// Number of rows, including expired ones.
    pub items: i64,
    /// Number of expired rows.
    pub expired: i64,
    /// Total size of the encrypted values in bytes.
    pub encrypted_value_bytes: i64,
}

/// An open store.
pub struct Source {
    conn: Conn,
    profiles: Vec<Profile>,
}

impl std::fmt::Debug for Source {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Source(<redacted>)")
    }
}

impl Source {
    /// Connect read-only and unlock every profile key.
    pub async fn open(uri: &str, pass_key_env: Option<&str>) -> Result<Self> {
        Self::open_with(uri, |key_reference| {
            read_pass_key(key_reference, pass_key_env)
        })
        .await
    }

    /// Connect read-only and unlock every profile key, asking `pass_key` for the pass key
    /// once the store's key method is known (`none` means the store has no pass key).
    pub async fn open_with(
        uri: &str,
        pass_key: impl FnOnce(&str) -> Result<PassKey<'static>>,
    ) -> Result<Self> {
        let mut conn = if uri.starts_with("sqlite:") {
            Conn::Sqlite(inspect::sqlite::open(uri).await?)
        } else if uri.starts_with("postgres:") || uri.starts_with("postgresql:") {
            Conn::Postgres(inspect::postgres::open(uri).await?)
        } else {
            bail!("Expected an Askar sqlite: or postgres: URI");
        };
        let key_reference = on_conn!(&mut conn, reads, c => reads::key_reference(c).await)?;
        let raw = on_conn!(&mut conn, reads, c => reads::profiles(c).await)?;
        let pass_key = pass_key(&key_reference)?;
        let key = InspectionKey::resolve(&key_reference, pass_key)?;
        let profiles = raw
            .into_iter()
            .map(|profile| {
                let inspector = match profile.profile_key {
                    Some(wrapped) => key
                        .unlock(wrapped)
                        .map(Arc::new)
                        .map_err(|error| error.to_string()),
                    None => Err("Missing profile key".to_owned()),
                };
                Profile {
                    id: profile.id,
                    name: profile.name,
                    inspector,
                }
            })
            .collect();
        Ok(Self { conn, profiles })
    }

    /// All profiles, or the one with the given name.
    pub fn select_profiles(&self, name: Option<&str>) -> Result<Vec<Profile>> {
        let selected: Vec<Profile> = self
            .profiles
            .iter()
            .filter(|profile| match name {
                Some(name) => profile.name == name,
                None => true,
            })
            .cloned()
            .collect();
        if selected.is_empty() {
            match name {
                Some(name) => bail!("Profile {name:?} not found"),
                None => bail!("The store has no profiles"),
            }
        }
        Ok(selected)
    }

    /// Count rows and encrypted value bytes per profile, kind and category.
    pub async fn stats(&mut self) -> Result<Vec<Stat>> {
        let raw = on_conn!(&mut self.conn, reads, c => reads::stats(c).await)?;
        let mut stats = Vec::with_capacity(raw.len());
        for stat in raw {
            let Some(profile) = self.profiles.iter().find(|p| p.id == stat.profile_id) else {
                continue;
            };
            let category = match &profile.inspector {
                Ok(inspector) => inspector
                    .decrypt_category(stat.category)
                    .unwrap_or_else(|error| format!("<undecryptable: {error}>")),
                Err(_) => "<profile locked>".to_owned(),
            };
            stats.push(Stat {
                profile: profile.name.clone(),
                kind: stat.kind,
                category,
                items: stat.items,
                expired: stat.expired,
                encrypted_value_bytes: stat.value_bytes,
            });
        }
        Ok(stats)
    }

    /// Fetch and decrypt the next page of matching rows after `after_id`.
    pub async fn scan(
        &mut self,
        profile: &Profile,
        query: &Query,
        after_id: i64,
        limit: i64,
    ) -> Result<Vec<InspectedItem>> {
        let inspector = profile.inspector()?;
        let filter = RawFilter {
            id: query.id,
            kind: query.kind,
            category: query
                .category
                .as_deref()
                .map(|category| inspector.encrypt_category(category))
                .transpose()?,
            name: query
                .name
                .as_deref()
                .map(|name| inspector.encrypt_name(name))
                .transpose()?,
            tags: query
                .tags
                .iter()
                .map(|tag| inspector.tag_filter(&tag.name, &tag.value, tag.plaintext))
                .collect::<Result<_, _>>()?,
            expiry: query.expiry,
        };
        let rows = on_conn!(
            &mut self.conn,
            reads,
            c => reads::scan(c, Some(profile.id), &filter, after_id, limit).await
        )?;
        Ok(rows.into_iter().map(|row| inspector.decrypt(row)).collect())
    }

    /// Fetch and decrypt one row by its database ID, regardless of expiry.
    pub async fn fetch(&mut self, profile: &Profile, id: i64) -> Result<Option<InspectedItem>> {
        let inspector = profile.inspector()?;
        let row = on_conn!(&mut self.conn, reads, c => reads::fetch(c, profile.id, id).await)?;
        Ok(row.map(|row| inspector.decrypt(row)))
    }
}
