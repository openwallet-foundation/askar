//! Read-only decryption of raw storage records for diagnostic tools.

use crate::{
    crypto::buffer::SecretBytes,
    entry::EntryTag,
    protect::{EntryEncryptor, PassKey, ProfileKey, StoreKey, StoreKeyReference},
    Error,
};

/// Defines the scan, fetch and stats readers shared by the SQL backends.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
macro_rules! impl_raw_reads {
    ($connection:ty, $db:ty, $expired_sql:expr) => {
        /// Fetch the next page of rows (with tags) matching `filter`, ordered by ID.
        pub async fn scan(
            connection: &mut $connection,
            profile_id: Option<i64>,
            filter: &$crate::inspect::RawFilter,
            after_id: i64,
            limit: i64,
        ) -> Result<Vec<$crate::inspect::RawItem>, $crate::Error> {
            use sqlx::Row;
            if limit <= 0 {
                return Err(err_msg!(Input, "Page size must be positive"));
            }
            let mut query = $crate::inspect::query::scan::<$db>(
                profile_id,
                filter,
                after_id,
                limit,
                $expired_sql,
            );
            let rows = query
                .build()
                .fetch_all(&mut *connection)
                .await
                .map_err(err_map!(Backend, "Error reading items"))?;
            let mut items = rows
                .into_iter()
                .map(|row| {
                    Ok($crate::inspect::RawItem {
                        id: row.try_get("id").map_err(err_map!(Backend))?,
                        kind: row.try_get("kind").map_err(err_map!(Backend))?,
                        category: row.try_get("category").map_err(err_map!(Backend))?,
                        name: row.try_get("name").map_err(err_map!(Backend))?,
                        value: row.try_get("value").map_err(err_map!(Backend))?,
                        expiry: row.try_get("expiry").map_err(err_map!(Backend))?,
                        tags: Vec::new(),
                    })
                })
                .collect::<Result<Vec<_>, $crate::Error>>()?;
            if items.is_empty() {
                return Ok(items);
            }
            let ids: Vec<i64> = items.iter().map(|item| item.id).collect();
            let mut query = $crate::inspect::query::tags::<$db>(&ids);
            let tags = query
                .build()
                .fetch_all(connection)
                .await
                .map_err(err_map!(Backend, "Error reading item tags"))?;
            for row in tags {
                let item_id: i64 = row.try_get("item_id").map_err(err_map!(Backend))?;
                let position = items
                    .binary_search_by_key(&item_id, |item| item.id)
                    .map_err(|_| err_msg!(Backend, "Tag has no item in inspection page"))?;
                let plaintext: i64 = row.try_get("plaintext").map_err(err_map!(Backend))?;
                items[position].tags.push($crate::inspect::RawTag {
                    name: row.try_get("name").map_err(err_map!(Backend))?,
                    value: row.try_get("value").map_err(err_map!(Backend))?,
                    plaintext: plaintext != 0,
                });
            }
            Ok(items)
        }

        /// Fetch the next page of every row in a profile, including expired and KMS rows.
        pub async fn page(
            connection: &mut $connection,
            profile_id: i64,
            after_id: i64,
            limit: i64,
        ) -> Result<Vec<$crate::inspect::RawItem>, $crate::Error> {
            scan(
                connection,
                Some(profile_id),
                &$crate::inspect::RawFilter::default(),
                after_id,
                limit,
            )
            .await
        }

        /// Fetch one row by its database ID, regardless of expiry or kind.
        pub async fn fetch(
            connection: &mut $connection,
            profile_id: i64,
            id: i64,
        ) -> Result<Option<$crate::inspect::RawItem>, $crate::Error> {
            let filter = $crate::inspect::RawFilter {
                id: Some(id),
                ..Default::default()
            };
            Ok(scan(connection, Some(profile_id), &filter, 0, 1)
                .await?
                .pop())
        }

        /// Count rows and value bytes per profile, kind and (encrypted) category.
        pub async fn stats(
            connection: &mut $connection,
        ) -> Result<Vec<$crate::inspect::RawStat>, $crate::Error> {
            use sqlx::Row;
            let sql = format!(
                "SELECT i.profile_id, CAST(i.kind AS BIGINT) AS kind, i.category,
                    CAST(COUNT(*) AS BIGINT) AS items,
                    CAST(COALESCE(SUM(LENGTH(i.value)), 0) AS BIGINT) AS value_bytes,
                    CAST(COALESCE(SUM(CASE WHEN {} THEN 1 ELSE 0 END), 0) AS BIGINT) AS expired
                 FROM items i GROUP BY i.profile_id, i.kind, i.category
                 ORDER BY i.profile_id, i.kind, items DESC",
                $expired_sql
            );
            let rows = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
                .fetch_all(connection)
                .await
                .map_err(err_map!(Backend, "Error reading store statistics"))?;
            rows.into_iter()
                .map(|row| {
                    Ok($crate::inspect::RawStat {
                        profile_id: row.try_get("profile_id").map_err(err_map!(Backend))?,
                        kind: row.try_get("kind").map_err(err_map!(Backend))?,
                        category: row.try_get("category").map_err(err_map!(Backend))?,
                        items: row.try_get("items").map_err(err_map!(Backend))?,
                        value_bytes: row.try_get("value_bytes").map_err(err_map!(Backend))?,
                        expired: row.try_get("expired").map_err(err_map!(Backend))?,
                    })
                })
                .collect()
        }
    };
}

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(any(feature = "sqlite", feature = "postgres"))]
mod query {
    use sqlx::{Database, Encode, QueryBuilder, Type};

    use super::{ExpiryFilter, RawFilter};

    pub fn scan<DB>(
        profile_id: Option<i64>,
        filter: &RawFilter,
        after_id: i64,
        limit: i64,
        expired_sql: &str,
    ) -> QueryBuilder<DB>
    where
        DB: Database,
        i64: for<'e> Encode<'e, DB> + Type<DB>,
        Vec<u8>: for<'e> Encode<'e, DB> + Type<DB>,
    {
        let mut query = QueryBuilder::new(
            "SELECT i.id, CAST(i.kind AS BIGINT) AS kind, i.category, i.name, i.value, i.expiry \
             FROM items i WHERE i.id > ",
        );
        query.push_bind(after_id);
        if let Some(profile_id) = profile_id {
            query.push(" AND i.profile_id = ").push_bind(profile_id);
        }
        if let Some(id) = filter.id {
            query.push(" AND i.id = ").push_bind(id);
        }
        if let Some(kind) = filter.kind {
            query.push(" AND i.kind = ").push_bind(kind);
        }
        if let Some(category) = &filter.category {
            query.push(" AND i.category = ").push_bind(category.clone());
        }
        if let Some(name) = &filter.name {
            query.push(" AND i.name = ").push_bind(name.clone());
        }
        match filter.expiry {
            ExpiryFilter::Any => {}
            ExpiryFilter::LiveOnly => {
                query.push(" AND NOT ").push(expired_sql);
            }
            ExpiryFilter::ExpiredOnly => {
                query.push(" AND ").push(expired_sql);
            }
        }
        for tag in &filter.tags {
            query
                .push(
                    " AND EXISTS (SELECT 1 FROM items_tags t WHERE t.item_id = i.id AND t.name = ",
                )
                .push_bind(tag.name.clone())
                .push(" AND t.value = ")
                .push_bind(tag.value.clone())
                // literal: the column is a boolean in SQLite and a smallint in Postgres
                .push(if tag.plaintext {
                    " AND t.plaintext = 1)"
                } else {
                    " AND t.plaintext = 0)"
                });
        }
        query.push(" ORDER BY i.id LIMIT ").push_bind(limit);
        query
    }

    pub fn tags<DB>(item_ids: &[i64]) -> QueryBuilder<DB>
    where
        DB: Database,
        i64: for<'e> Encode<'e, DB> + Type<DB>,
    {
        let mut query = QueryBuilder::new(
            "SELECT it.item_id, it.name, it.value, CAST(it.plaintext AS BIGINT) AS plaintext \
             FROM items_tags it WHERE it.item_id IN (",
        );
        let mut ids = query.separated(", ");
        for id in item_ids {
            ids.push_bind(*id);
        }
        query.push(") ORDER BY it.item_id, it.id");
        query
    }
}

/// Which rows a raw scan returns with respect to their expiry time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExpiryFilter {
    /// Return live and expired rows.
    #[default]
    Any,
    /// Return only rows that have not expired.
    LiveOnly,
    /// Return only rows that have expired.
    ExpiredOnly,
}

/// A tag condition already encrypted for the profile being scanned.
#[derive(Clone, Debug)]
pub struct RawTagFilter {
    /// Encrypted tag name.
    pub name: Vec<u8>,
    /// Encrypted value, or UTF-8 bytes for a plaintext tag.
    pub value: Vec<u8>,
    /// Whether the tag value is stored as plaintext.
    pub plaintext: bool,
}

/// Equality conditions for a raw scan; unset fields do not restrict the result.
#[derive(Clone, Debug, Default)]
pub struct RawFilter {
    /// Database row identifier.
    pub id: Option<i64>,
    /// Entry kind discriminator.
    pub kind: Option<i64>,
    /// Encrypted category.
    pub category: Option<Vec<u8>>,
    /// Encrypted name.
    pub name: Option<Vec<u8>>,
    /// Tags that must all be present on the row.
    pub tags: Vec<RawTagFilter>,
    /// Expiry restriction.
    pub expiry: ExpiryFilter,
}

/// Row counts for one profile, kind and encrypted category.
#[derive(Debug)]
pub struct RawStat {
    /// Profile row identifier.
    pub profile_id: i64,
    /// Stored kind discriminator.
    pub kind: i64,
    /// Encrypted category.
    pub category: Vec<u8>,
    /// Number of rows, including expired ones.
    pub items: i64,
    /// Total size of the encrypted values in bytes.
    pub value_bytes: i64,
    /// Number of rows that have already expired.
    pub expired: i64,
}

/// A profile with its wrapped key, including profiles with a missing key.
#[derive(Debug)]
pub struct RawProfile {
    /// Database row identifier.
    pub id: i64,
    /// Profile name.
    pub name: String,
    /// Serialized, possibly wrapped profile key.
    pub profile_key: Option<Vec<u8>>,
}

/// A tag as stored in `items_tags`.
#[derive(Debug)]
pub struct RawTag {
    /// Encrypted tag name.
    pub name: Vec<u8>,
    /// Encrypted value, or UTF-8 bytes for a plaintext tag.
    pub value: Vec<u8>,
    /// Whether the value is stored as plaintext.
    pub plaintext: bool,
}

/// Encrypted fields of an item, including rows excluded by regular scans.
#[derive(Debug)]
pub struct RawItem {
    /// Database row identifier.
    pub id: i64,
    /// Stored kind discriminator (including unknown values).
    pub kind: i64,
    /// Encrypted category.
    pub category: Vec<u8>,
    /// Encrypted name.
    pub name: Vec<u8>,
    /// Encrypted value.
    pub value: Vec<u8>,
    /// Expiry timestamp, if present.
    pub expiry: Option<chrono::NaiveDateTime>,
    /// Tags belonging to the row.
    pub tags: Vec<RawTag>,
}

/// Decrypted fields, each with its own error so damaged rows remain inspectable.
#[derive(Debug)]
pub struct InspectedItem {
    /// Database row identifier.
    pub id: i64,
    /// Stored kind discriminator.
    pub kind: i64,
    /// Decrypted category.
    pub category: Result<String, Error>,
    /// Decrypted name.
    pub name: Result<String, Error>,
    /// Decrypted value.
    pub value: Result<SecretBytes, Error>,
    /// Expiry timestamp, if present.
    pub expiry: Option<chrono::NaiveDateTime>,
    /// Independently decrypted tags.
    pub tags: Vec<Result<EntryTag, Error>>,
}

/// A profile key unlocked using the store's recorded key method.
pub struct Inspector {
    key: ProfileKey,
}

/// A resolved store key that can unlock multiple profiles without repeating key derivation.
pub struct InspectionKey {
    store_key: StoreKey,
}

impl std::fmt::Debug for InspectionKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("InspectionKey(<redacted>)")
    }
}

impl InspectionKey {
    /// Resolve the store's recorded key reference once.
    pub fn resolve(key_reference: &str, pass_key: PassKey<'_>) -> Result<Self, Error> {
        Ok(Self {
            store_key: StoreKeyReference::parse_uri(key_reference)?.resolve(pass_key)?,
        })
    }

    /// Unlock a profile key with this store key.
    pub fn unlock(&self, wrapped_profile_key: Vec<u8>) -> Result<Inspector, Error> {
        let profile_key = self.store_key.unwrap_data(wrapped_profile_key)?;
        Ok(Inspector {
            key: ProfileKey::from_slice(profile_key.as_ref())?,
        })
    }
}

impl std::fmt::Debug for Inspector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Inspector(<redacted>)")
    }
}

impl Inspector {
    /// Unlock a profile key with the key reference stored in `config.key`.
    pub fn unlock(
        key_reference: &str,
        pass_key: PassKey<'_>,
        wrapped_profile_key: Vec<u8>,
    ) -> Result<Self, Error> {
        InspectionKey::resolve(key_reference, pass_key)?.unlock(wrapped_profile_key)
    }

    /// Encrypt a category so it can be used in a [`RawFilter`].
    pub fn encrypt_category(&self, category: &str) -> Result<Vec<u8>, Error> {
        self.key
            .encrypt_entry_category(ProfileKey::prepare_input(category.as_bytes()))
    }

    /// Encrypt an entry name so it can be used in a [`RawFilter`].
    pub fn encrypt_name(&self, name: &str) -> Result<Vec<u8>, Error> {
        self.key
            .encrypt_entry_name(ProfileKey::prepare_input(name.as_bytes()))
    }

    /// Build a tag condition; encrypted tag values can only be matched exactly.
    pub fn tag_filter(
        &self,
        name: &str,
        value: &str,
        plaintext: bool,
    ) -> Result<RawTagFilter, Error> {
        let value = if plaintext {
            value.as_bytes().to_vec()
        } else {
            self.key
                .encrypt_tag_value(ProfileKey::prepare_input(value.as_bytes()))?
        };
        Ok(RawTagFilter {
            name: self
                .key
                .encrypt_tag_name(ProfileKey::prepare_input(name.as_bytes()))?,
            value,
            plaintext,
        })
    }

    /// Decrypt a category taken from a [`RawStat`].
    pub fn decrypt_category(&self, category: Vec<u8>) -> Result<String, Error> {
        self.key.decrypt_entry_category(category)
    }

    /// Decrypt one raw row without losing other fields when a field is damaged.
    pub fn decrypt(&self, raw: RawItem) -> InspectedItem {
        let category = self.key.decrypt_entry_category(raw.category);
        let name = self.key.decrypt_entry_name(raw.name);
        let value = match (&category, &name) {
            (Ok(category), Ok(name)) => {
                self.key
                    .decrypt_entry_value(category.as_bytes(), name.as_bytes(), raw.value)
            }
            _ => Err(err_msg!(
                Encryption,
                "Cannot decrypt value without category and name"
            )),
        };
        let tags = raw
            .tags
            .into_iter()
            .map(|tag| {
                let name = self.key.decrypt_tag_name(tag.name)?;
                let name = String::from_utf8(name.into_vec())
                    .map_err(err_map!(Encryption, "Invalid tag name"))?;
                let value = if tag.plaintext {
                    tag.value
                } else {
                    self.key.decrypt_tag_value(tag.value)?.into_vec()
                };
                let value =
                    String::from_utf8(value).map_err(err_map!(Encryption, "Invalid tag value"))?;
                Ok(if tag.plaintext {
                    EntryTag::Plaintext(name, value)
                } else {
                    EntryTag::Encrypted(name, value)
                })
            })
            .collect();
        InspectedItem {
            id: raw.id,
            kind: raw.kind,
            category,
            name,
            value,
            expiry: raw.expiry,
            tags,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protect::EntryEncryptor;

    #[test]
    fn decrypts_fields_independently() {
        let profile = ProfileKey::new().unwrap();
        let inspector = Inspector::unlock(
            "none",
            PassKey::empty(),
            profile.to_bytes().unwrap().into_vec(),
        )
        .unwrap();
        let mut value = profile
            .encrypt_entry_value(b"records", b"first", SecretBytes::from(b"hello".as_slice()))
            .unwrap();
        value[12] ^= 1;
        let raw = RawItem {
            id: 3,
            kind: 2,
            category: profile
                .encrypt_entry_category(b"records".as_slice().into())
                .unwrap(),
            name: profile
                .encrypt_entry_name(b"first".as_slice().into())
                .unwrap(),
            value,
            expiry: Some(chrono::DateTime::from_timestamp(12, 0).unwrap().naive_utc()),
            tags: vec![RawTag {
                name: profile
                    .encrypt_tag_name(b"status".as_slice().into())
                    .unwrap(),
                value: b"active".to_vec(),
                plaintext: true,
            }],
        };
        let item = inspector.decrypt(raw);
        assert_eq!(item.category.unwrap(), "records");
        assert_eq!(item.name.unwrap(), "first");
        assert!(item.value.is_err());
        assert_eq!(
            item.tags[0].as_ref().unwrap(),
            &EntryTag::Plaintext("status".into(), "active".into())
        );
        assert_eq!(
            item.expiry,
            Some(chrono::DateTime::from_timestamp(12, 0).unwrap().naive_utc())
        );
    }
}
