//! Read-only access to SQLite storage rows without expiry or kind filtering.

use std::str::FromStr;

use sqlx::{sqlite::SqliteConnectOptions, Connection, Row, SqliteConnection};

use super::RawProfile;
use crate::{backend::sqlite::SqliteStoreOptions, Error};

const EXPIRED_SQL: &str = "(i.expiry IS NOT NULL AND DATETIME(i.expiry) <= DATETIME('now'))";

impl_raw_reads!(SqliteConnection, sqlx::Sqlite, EXPIRED_SQL);

/// Open a SQLite store read-only in a snapshot transaction.
pub async fn open(uri: &str) -> Result<SqliteConnection, Error> {
    let options = SqliteStoreOptions::new(uri)?;
    let connect = SqliteConnectOptions::from_str(&options.path)
        .map_err(err_map!(Input, "Invalid SQLite path"))?
        .read_only(true);
    let mut connection = SqliteConnection::connect_with(&connect)
        .await
        .map_err(err_map!(Backend, "Error opening SQLite store"))?;
    sqlx::query("BEGIN")
        .execute(&mut connection)
        .await
        .map_err(err_map!(Backend, "Error starting inspection snapshot"))?;
    Ok(connection)
}

/// Read the wrapping-key reference recorded in the database.
pub async fn key_reference(connection: &mut SqliteConnection) -> Result<String, Error> {
    let version: String = sqlx::query_scalar("SELECT value FROM config WHERE name = 'version'")
        .fetch_one(&mut *connection)
        .await
        .map_err(err_map!(Backend, "Error reading store version"))?;
    if version != "1" {
        return Err(err_msg!(Unsupported, "Unsupported store version"));
    }
    sqlx::query_scalar("SELECT value FROM config WHERE name = 'key'")
        .fetch_one(connection)
        .await
        .map_err(err_map!(Backend, "Error reading store key reference"))
}

/// List profiles without attempting to decrypt their keys.
pub async fn profiles(connection: &mut SqliteConnection) -> Result<Vec<RawProfile>, Error> {
    let rows = sqlx::query("SELECT id, name, profile_key FROM profiles ORDER BY id")
        .fetch_all(connection)
        .await
        .map_err(err_map!(Backend, "Error reading profiles"))?;
    rows.into_iter()
        .map(|row| {
            Ok(RawProfile {
                id: row.try_get("id").map_err(err_map!(Backend))?,
                name: row.try_get("name").map_err(err_map!(Backend))?,
                profile_key: row.try_get("profile_key").map_err(err_map!(Backend))?,
            })
        })
        .collect()
}
