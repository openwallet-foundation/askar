//! Read-only access to PostgreSQL storage rows without expiry or kind filtering.

use std::str::FromStr;

use sqlx::{postgres::PgConnectOptions, Connection, PgConnection, Row};

use super::RawProfile;
use crate::{backend::postgres::PostgresStoreOptions, Error};

const EXPIRED_SQL: &str = "(i.expiry IS NOT NULL AND i.expiry <= CURRENT_TIMESTAMP)";

impl_raw_reads!(PgConnection, sqlx::Postgres, EXPIRED_SQL);

/// Open a Postgres store in a read-only, repeatable-read transaction.
pub async fn open(uri: &str) -> Result<PgConnection, Error> {
    let options = PostgresStoreOptions::new(uri)?;
    let mut connect = PgConnectOptions::from_str(&options.uri)
        .map_err(err_map!(Input, "Invalid Postgres URI"))?
        .options([("default_transaction_read_only", "on")]);
    if let Some(schema) = &options.schema {
        connect = connect.options([("search_path", schema.as_str())]);
    }
    let mut connection = PgConnection::connect_with(&connect)
        .await
        .map_err(err_map!(Backend, "Error opening Postgres store"))?;
    sqlx::query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut connection)
        .await
        .map_err(err_map!(Backend, "Error starting inspection snapshot"))?;
    Ok(connection)
}

/// Read the wrapping-key reference recorded in the database.
pub async fn key_reference(connection: &mut PgConnection) -> Result<String, Error> {
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
pub async fn profiles(connection: &mut PgConnection) -> Result<Vec<RawProfile>, Error> {
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
