//! Support for migration from Indy-SDK wallets.

use sha2::Sha256;
use sqlx::sqlite::SqliteRow;
use sqlx::{Connection, Row, SqliteConnection};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use self::strategy::Strategy;
use crate::backend::sqlite::SqliteStoreOptions;
use crate::backend::Backend;
use crate::crypto::alg::chacha20::{Chacha20Key, C20P};
use crate::crypto::generic_array::typenum::U32;
use crate::entry::EncEntryTag;
use crate::error::Error;
use crate::protect::kdf::Argon2Level;
use crate::protect::{ProfileKey, StoreKey, StoreKeyReference};

mod strategy;

const CHACHAPOLY_NONCE_LEN: u8 = 12;

#[derive(Deserialize, Debug, Default)]
pub(crate) struct IndyKeyMetadata {
    keys: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    master_key_salt: Option<Vec<u8>>,
}

pub(crate) type EncryptionKey = Chacha20Key<C20P>;
pub(crate) type MacKey = crate::protect::hmac_key::HmacKey<Sha256, U32>;

/// Copies: https://github.com/hyperledger/indy-sdk/blob/83547c4c01162f6323cf138f8b071da2e15f0c90/libindy/indy-wallet/src/wallet.rs#L18
#[derive(Deserialize)]
pub(crate) struct IndyKey {
    type_key: EncryptionKey,
    name_key: EncryptionKey,
    value_key: EncryptionKey,
    #[allow(unused)]
    item_hmac_key: MacKey,
    tag_name_key: EncryptionKey,
    tag_value_key: EncryptionKey,
    #[allow(unused)]
    tag_hmac_key: MacKey,
}

#[derive(Default)]
pub(crate) struct UpdatedIndyItem {
    pub id: u32,
    pub category: Vec<u8>,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub tags: Vec<EncEntryTag>,
}

pub(crate) struct UpdatedKey {
    master: StoreKey,
    key_ref: StoreKeyReference,
}

#[derive(Debug)]
pub(crate) enum KdfMethod {
    Argon2i(Argon2Level),
    Raw,
}

impl KdfMethod {
    pub(crate) fn to_store_key_reference(
        &self,
        salt: Option<&[u8]>,
    ) -> Result<StoreKeyReference, Error> {
        match self {
            KdfMethod::Raw => Ok(StoreKeyReference::RawKey),
            KdfMethod::Argon2i(level) => {
                let detail = salt
                    .map(|s| format!("?salt={}", hex::encode(s)))
                    .ok_or_else(|| err_msg!("Salt must be provided for argon2i kdf method"))?;
                Ok(StoreKeyReference::DeriveKey(
                    crate::protect::kdf::KdfMethod::Argon2i(*level),
                    detail,
                ))
            }
        }
    }
}

impl FromStr for KdfMethod {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ARGON2I_MOD" => Ok(Self::Argon2i(Argon2Level::Moderate)),
            "ARGON2I_INT" => Ok(Self::Argon2i(Argon2Level::Interactive)),
            "RAW" => Ok(Self::Raw),
            _ => Err(err_msg!("Invalid key derivation method")),
        }
    }
}

/// Indy-SDK migrator implementation
#[derive(Debug)]
pub struct IndySdkToAriesAskarMigration {
    conn: SqliteConnection,
    spec_uri: String,
    wallet_key: String,
    wallet_name: String,
    kdf_method: KdfMethod,
}

impl IndySdkToAriesAskarMigration {
    /// Create a new migrator connected to a database
    pub async fn connect(
        spec_uri: &str,
        wallet_name: &str,
        wallet_key: &str,
        kdf_method: &str,
    ) -> Result<Self, Error> {
        let kdf_method = KdfMethod::from_str(kdf_method)?;
        let conn = SqliteConnection::connect(spec_uri).await?;
        Ok(Self {
            conn,
            spec_uri: spec_uri.into(),
            wallet_key: wallet_key.to_owned(),
            wallet_name: wallet_name.to_owned(),
            kdf_method,
        })
    }

    /// Close the instance without migrating
    pub async fn close(self) -> Result<(), Error> {
        Ok(self.conn.close().await?)
    }

    /// Perform the migration
    pub async fn migrate(mut self) -> Result<(), Error> {
        if self.is_migrated().await? {
            self.close().await?;
            return Err(err_msg!(Backend, "Database is already migrated"));
        }

        self.pre_upgrade().await?;
        debug!("Completed wallet pre-upgrade");

        let (indy_key, upd_key) = self.fetch_indy_key().await?;
        self.create_config(&upd_key).await?;
        let profile_key = self.init_profile(&upd_key).await?;
        debug!("Created wallet profile");

        self.update_items(&indy_key, &profile_key).await?;
        self.finish_upgrade().await?;
        self.conn.close().await?;
        debug!("Completed wallet upgrade");

        debug!("Re-opening wallet");
        let db_opts = SqliteStoreOptions::new(self.spec_uri.as_str())?;
        let key_method = upd_key.key_ref.into();
        let db = db_opts
            .open(Some(key_method), self.wallet_key.as_str().into(), None)
            .await?;
        db.close().await?;
        debug!("Verified wallet upgrade");

        Ok(())
    }

    #[inline]
    async fn is_migrated(&mut self) -> Result<bool, Error> {
        let res: Option<SqliteRow> =
            sqlx::query("SELECT name FROM sqlite_master WHERE type='table' AND name='metadata'")
                .fetch_optional(&mut self.conn)
                .await?;
        Ok(res.is_none())
    }

    async fn pre_upgrade(&mut self) -> Result<(), Error> {
        sqlx::query(
            "
            BEGIN EXCLUSIVE TRANSACTION;
                CREATE TABLE config (
                    name TEXT NOT NULL,
                    value TEXT,
                    PRIMARY KEY (name)
                );
                 CREATE TABLE profiles (
                    id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    reference TEXT NULL,
                    profile_key BLOB NULL,
                    PRIMARY KEY (id)
                 );
                 CREATE UNIQUE INDEX ix_profile_name ON profiles (name);
                 ALTER TABLE items RENAME TO items_old;
                 CREATE TABLE items (
                    id INTEGER NOT NULL,
                    profile_id INTEGER NOT NULL,
                    kind INTEGER NOT NULL,
                    category BLOB NOT NULL,
                    name BLOB NOT NULL,
                    value BLOB NOT NULL,
                    expiry DATETIME NULL,
                    PRIMARY KEY (id),
                    FOREIGN KEY (profile_id) REFERENCES profiles (id)
                        ON DELETE CASCADE ON UPDATE CASCADE
                 );
                 CREATE UNIQUE INDEX ix_items_uniq ON items
                     (profile_id, kind, category, name);
                 CREATE TABLE items_tags (
                     id INTEGER NOT NULL,
                     item_id INTEGER NOT NULL,
                     name BLOB NOT NULL,
                     value BLOB NOT NULL,
                     plaintext BOOLEAN NOT NULL,
                     PRIMARY KEY (id),
                     FOREIGN KEY (item_id) REFERENCES items (id)
                         ON DELETE CASCADE ON UPDATE CASCADE
                 );
                 CREATE INDEX ix_items_tags_item_id ON items_tags (item_id);
                 CREATE INDEX ix_items_tags_name_enc ON items_tags
                     (name, SUBSTR(value, 1, 12)) WHERE plaintext=0;
                 CREATE INDEX ix_items_tags_name_plain ON items_tags
                     (name, value) WHERE plaintext=1;
                 COMMIT;
                 ",
        )
        .execute(&mut self.conn)
        .await?;
        Ok(())
    }

    async fn fetch_indy_key(&mut self) -> Result<(IndyKey, UpdatedKey), Error> {
        let metadata_row: Vec<u8> = sqlx::query("SELECT value FROM metadata")
            .fetch_one(&mut self.conn)
            .await?
            .try_get(0)?;
        let metadata_json = String::from_utf8_lossy(&metadata_row);
        let metadata: IndyKeyMetadata = serde_json::from_str(&metadata_json).map_err(err_map!(
            Input,
            "Could not convert value from metadata to IndyKey",
        ))?;
        let keys_enc = metadata.keys;
        let salt = metadata.master_key_salt.map(|s| s[..16].to_vec());

        let key_ref = self.kdf_method.to_store_key_reference(salt.as_deref())?;
        let master = key_ref.resolve(self.wallet_key.as_str().into())?;

        let keys_mpk = master
            .unwrap_data(keys_enc)
            .map_err(err_map!(Input, "Error decrypting wallet key"))?;
        let indy_key = rmp_serde::from_slice(&keys_mpk)
            .map_err(err_map!(Input, "indy key not valid msgpack"))?;

        Ok((indy_key, UpdatedKey { master, key_ref }))
    }

    async fn init_profile(&mut self, key: &UpdatedKey) -> Result<ProfileKey, Error> {
        let profile_row: Option<SqliteRow> = sqlx::query("SELECT profile_key FROM profiles")
            .fetch_optional(&mut self.conn)
            .await?;
        let profile_row: Option<Vec<u8>> = match profile_row {
            Some(row) => row.try_get(0).ok(),
            None => None,
        };

        let profile_key = match profile_row {
            Some(profile_row) => ciborium::from_reader(&profile_row[..])
                .map_err(err_map!(Input, "Invalid cbor encoding for profile_key"))?,
            None => {
                let pk = ProfileKey::new()?;
                let enc_pk = key.master.wrap_data(pk.to_bytes()?)?;
                self.insert_profile(enc_pk.as_slice()).await?;
                pk
            }
        };

        Ok(profile_key)
    }

    async fn update_items(
        &mut self,
        indy_key: &IndyKey,
        profile_key: &ProfileKey,
    ) -> Result<(), Error> {
        Strategy::update_items(self, indy_key, profile_key).await?;
        Ok(())
    }

    async fn finish_upgrade(&mut self) -> Result<(), Error> {
        sqlx::query(
            r#"
        BEGIN EXCLUSIVE TRANSACTION;
        DROP TABLE items_old;
        DROP TABLE metadata;
        DROP TABLE tags_encrypted;
        DROP TABLE tags_plaintext;
        INSERT INTO config (name, value) VALUES ("version", "1");
        COMMIT;"#,
        )
        .execute(&mut self.conn)
        .await?;
        Ok(())
    }

    async fn update_items_in_db(&mut self, items: Vec<UpdatedIndyItem>) -> Result<(), Error> {
        let mut del_ids = vec![];

        for item in items {
            del_ids.push(item.id);
            let ins = sqlx::query(
                "INSERT INTO items (profile_id, kind, category, name, value)
            VALUES (1, 2, ?1, ?2, ?3)",
            )
            .bind(item.category)
            .bind(item.name)
            .bind(item.value)
            .execute(&mut self.conn)
            .await?;
            let item_id = ins.last_insert_rowid();
            for EncEntryTag {
                name,
                value,
                plaintext,
            } in item.tags
            {
                sqlx::query("INSERT INTO items_tags (item_id, plaintext, name, value) VALUES (?1, ?2, ?3, ?4)")
                .bind(item_id)
                .bind(plaintext)
                .bind(name)
                .bind(value)
                .execute(&mut self.conn)
                .await?;
            }
        }
        sqlx::query("DELETE FROM items_old WHERE id IN (?1)")
            .bind(Separated(&del_ids, ",").to_string())
            .execute(&mut self.conn)
            .await?;
        Ok(())
    }

    async fn create_config(&mut self, key: &UpdatedKey) -> Result<(), Error> {
        let pass_key = key.key_ref.clone().into_uri();

        sqlx::query("INSERT INTO config (name, value) VALUES (?1, ?2)")
            .bind("default_profile")
            .bind(&self.wallet_name)
            .execute(&mut self.conn)
            .await?;

        sqlx::query("INSERT INTO config (name, value) VALUES (?1, ?2)")
            .bind("key")
            .bind(pass_key)
            .execute(&mut self.conn)
            .await?;

        Ok(())
    }

    async fn insert_profile(&mut self, key: &[u8]) -> Result<(), Error> {
        sqlx::query("INSERT INTO profiles (name, profile_key) VALUES (?1, ?2)")
            .bind(&self.wallet_name)
            .bind(key.to_vec())
            .execute(&mut self.conn)
            .await?;

        Ok(())
    }

    async fn fetch_pending_items<
        T: Send + Unpin + for<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow>,
    >(
        &mut self,
        limit: u8,
    ) -> Result<Option<Vec<T>>, Error> {
        let res = sqlx::query_as(
            "SELECT i.id, i.type, i.name, i.value, i.key,
        (SELECT GROUP_CONCAT(HEX(te.name) || ':' || HEX(te.value))
            FROM tags_encrypted te WHERE te.item_id = i.id) AS tags_enc,
        (SELECT GROUP_CONCAT(HEX(tp.name) || ':' || HEX(tp.value))
            FROM tags_plaintext tp WHERE tp.item_id = i.id) AS tags_plain
        FROM items_old i LIMIT ?1",
        )
        .bind(limit)
        .fetch_all(&mut self.conn)
        .await?;

        match res.len() {
            0 => Ok(None),
            _ => Ok(Some(res)),
        }
    }
}

struct Separated<'a, T>(&'a [T], &'static str);

impl<T: Display> Display for Separated<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for item in self.0 {
            if !first {
                f.write_str(self.1)?;
            }
            item.fmt(f)?;
            first = false;
        }
        Ok(())
    }
}
