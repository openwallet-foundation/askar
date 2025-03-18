use std::borrow::Cow;
use std::str::FromStr;
use std::time::Duration;

use sqlx::{
    postgres::{PgConnectOptions, PgConnection, PgPool, PgPoolOptions, Postgres},
    ConnectOptions, Connection, Error as SqlxError, Executor, Row, Transaction,
};

use crate::{
    backend::{
        db_utils::{init_keys, random_profile_name},
        ManageBackend,
    },
    error::Error,
    future::{unblock, BoxFuture},
    options::IntoOptions,
    protect::{KeyCache, PassKey, ProfileId, StoreKeyMethod, StoreKeyReference},
};

use super::PostgresBackend;

const DEFAULT_CONNECT_TIMEOUT: u64 = 30;
const DEFAULT_IDLE_TIMEOUT: u64 = 300;
const DEFAULT_MIN_CONNECTIONS: u32 = 0;
const DEFAULT_MAX_CONNECTIONS: u32 = 10;

/// Configuration options for PostgreSQL stores
#[derive(Debug)]
pub struct PostgresStoreOptions {
    pub(crate) connect_timeout: Duration,
    pub(crate) idle_timeout: Duration,
    pub(crate) max_connections: u32,
    pub(crate) min_connections: u32,
    pub(crate) uri: String,
    pub(crate) admin_uri: String,
    pub(crate) host: String,
    pub(crate) name: String,
    pub(crate) username: String,
    pub(crate) schema: Option<String>,
}

impl PostgresStoreOptions {
    /// Initialize `PostgresStoreOptions` from a generic set of options
    pub fn new<'a, O>(options: O) -> Result<Self, Error>
    where
        O: IntoOptions<'a>,
    {
        let mut opts = options.into_options()?;
        let connect_timeout = if let Some(timeout) = opts.query.remove("connect_timeout") {
            timeout
                .parse()
                .map_err(err_map!(Input, "Error parsing 'connect_timeout' parameter"))?
        } else {
            DEFAULT_CONNECT_TIMEOUT
        };
        let idle_timeout = if let Some(timeout) = opts.query.remove("idle_timeout") {
            timeout
                .parse()
                .map_err(err_map!(Input, "Error parsing 'idle_timeout' parameter"))?
        } else {
            DEFAULT_IDLE_TIMEOUT
        };
        let max_connections = if let Some(max_conn) = opts.query.remove("max_connections") {
            max_conn
                .parse()
                .map_err(err_map!(Input, "Error parsing 'max_connections' parameter"))?
        } else {
            DEFAULT_MAX_CONNECTIONS
        };
        let min_connections = if let Some(min_conn) = opts.query.remove("min_connections") {
            min_conn
                .parse()
                .map_err(err_map!(Input, "Error parsing 'min_connections' parameter"))?
        } else {
            DEFAULT_MIN_CONNECTIONS
        };
        let schema = opts.query.remove("schema");
        let admin_acct = opts.query.remove("admin_account");
        let admin_pass = opts.query.remove("admin_password");
        let username = match opts.user.as_ref() {
            "" => "postgres".to_owned(),
            a => a.to_owned(),
        };
        let uri = opts.clone().into_uri();
        if admin_acct.is_some() || admin_pass.is_some() {
            if let Some(admin_acct) = admin_acct {
                opts.user = Cow::Owned(admin_acct);
            }
            if let Some(admin_pass) = admin_pass {
                opts.password = Cow::Owned(admin_pass);
            }
        }
        let host = opts.host.to_string();
        let path = opts.path.as_ref();
        if path.len() < 2 {
            return Err(err_msg!(Input, "Missing database name"));
        }
        let name = path[1..].to_string();
        if let Some(schema) = schema.as_ref() {
            _validate_ident(schema, "schema")?;
        }
        _validate_ident(&name, "database")?;
        _validate_ident(&username, "username")?;
        // admin user selects the default database
        opts.path = Cow::Borrowed("/postgres");
        Ok(Self {
            connect_timeout: Duration::from_secs(connect_timeout),
            idle_timeout: Duration::from_secs(idle_timeout),
            max_connections,
            min_connections,
            uri,
            admin_uri: opts.into_uri(),
            host,
            name,
            username,
            schema,
        })
    }

    async fn pool(&self) -> Result<PgPool, SqlxError> {
        #[allow(unused_mut)]
        let mut conn_opts = PgConnectOptions::from_str(self.uri.as_str())?;
        #[cfg(feature = "log")]
        {
            conn_opts = conn_opts
                .log_statements(log::LevelFilter::Debug)
                .log_slow_statements(log::LevelFilter::Debug, Default::default());
        }
        if let Some(s) = self.schema.as_ref() {
            // NB: schema is a validated identifier
            conn_opts = conn_opts.options([("search_path", s)]);
        }
        PgPoolOptions::default()
            .acquire_timeout(self.connect_timeout)
            .idle_timeout(self.idle_timeout)
            .max_connections(self.max_connections)
            .min_connections(self.min_connections)
            .test_before_acquire(false)
            .connect_with(conn_opts)
            .await
    }

    pub(crate) async fn create_db_pool(&self) -> Result<PgPool, Error> {
        // try connecting normally in case the database exists
        match self.pool().await {
            Ok(pool) => Ok(pool),
            Err(SqlxError::Database(db_err)) if db_err.code() == Some(Cow::Borrowed("3D000")) => {
                // error 3D000 is INVALID CATALOG NAME in postgres,
                // this indicates that the database does not exist
                let mut admin_conn = PgConnection::connect(self.admin_uri.as_ref())
                    .await
                    .map_err(err_map!(
                        Backend,
                        "Error creating admin connection to database"
                    ))?;
                // self.name and self.username are validated identifiers
                let create_q = format!(
                    "CREATE DATABASE \"{}\" OWNER \"{}\"",
                    self.name, self.username
                );
                match admin_conn.execute(create_q.as_str()).await {
                    Ok(_) => (),
                    Err(SqlxError::Database(db_err))
                        if db_err.code() == Some(Cow::Borrowed("23505"))
                            || db_err.code() == Some(Cow::Borrowed("42P04")) =>
                    {
                        // 23505 is 'duplicate key value violates unique constraint'
                        // 42P04 is 'duplicate database error'
                        // in either case, assume another connection created the database
                        // before we could and continue
                    }
                    Err(err) => {
                        admin_conn.close().await?;
                        return Err(err_msg!(Backend, "Error creating database").with_cause(err));
                    }
                }
                admin_conn.close().await?;
                Ok(self.pool().await?)
            }
            Err(err) => Err(err_msg!(Backend, "Error opening database").with_cause(err)),
        }
    }

    /// Provision a Postgres store from this set of configuration options
    pub async fn provision(
        self,
        method: StoreKeyMethod,
        pass_key: PassKey<'_>,
        profile: Option<String>,
        recreate: bool,
    ) -> Result<PostgresBackend, Error> {
        let conn_pool = self.create_db_pool().await?;
        let mut conn = conn_pool.acquire().await?;
        let mut txn = conn.begin().await?;

        if recreate {
            // remove expected tables
            reset_db(&mut txn).await?;
        } else {
            // check for presence of config table
            let count = if let Some(schema) = self.schema.as_ref() {
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM information_schema.tables
                        WHERE table_schema=?1 AND table_name='config'",
                )
                .persistent(false)
                .bind(schema)
                .fetch_one(txn.as_mut())
                .await
                .map_err(err_map!(Backend, "Error checking for existing store"))?
            } else {
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM information_schema.tables
                    WHERE table_schema=ANY (CURRENT_SCHEMAS(false)) AND table_name='config'",
                )
                .persistent(false)
                .fetch_one(txn.as_mut())
                .await
                .map_err(err_map!(Backend, "Error checking for existing store"))?
            };
            if count > 0 {
                // proceed to open, will fail if the version doesn't match
                return open_db(
                    conn_pool,
                    Some(method),
                    pass_key,
                    profile,
                    self.host,
                    self.name,
                )
                .await;
            }
        }

        // no 'config' table, assume empty database

        let (profile_key, enc_profile_key, store_key, store_key_ref) = unblock({
            let pass_key = pass_key.into_owned();
            move || init_keys(method, pass_key)
        })
        .await?;
        let default_profile = profile.unwrap_or_else(random_profile_name);
        let profile_id = init_db(
            txn,
            &default_profile,
            store_key_ref,
            enc_profile_key,
            self.schema.as_ref().unwrap_or(&self.username),
        )
        .await?;
        conn.return_to_pool().await;

        let mut key_cache = KeyCache::new(store_key);
        key_cache.add_profile_mut(default_profile.clone(), profile_id, profile_key);

        Ok(PostgresBackend::new(
            conn_pool,
            default_profile,
            key_cache,
            self.host,
            self.name,
        ))
    }

    /// Open an existing Postgres store from this set of configuration options
    pub async fn open(
        self,
        method: Option<StoreKeyMethod>,
        pass_key: PassKey<'_>,
        profile: Option<String>,
    ) -> Result<PostgresBackend, Error> {
        let pool = match self.pool().await {
            Ok(p) => Ok(p),
            Err(SqlxError::Database(db_err)) if db_err.code() == Some(Cow::Borrowed("3D000")) => {
                // error 3D000 is INVALID CATALOG NAME in postgres,
                // this indicates that the database does not exist
                Err(err_msg!(NotFound, "The requested database was not found"))
            }
            Err(err) => Err(err_msg!(Backend, "Error connecting to database pool").with_cause(err)),
        }?;
        open_db(pool, method, pass_key, profile, self.host, self.name).await
    }

    /// Remove an existing Postgres store defined by these configuration options
    pub async fn remove(self) -> Result<bool, Error> {
        let mut admin_conn = PgConnection::connect(self.admin_uri.as_ref())
            .await
            .map_err(err_map!(
                Backend,
                "Error creating admin connection to database"
            ))?;
        // any character except NUL is allowed in an identifier.
        // double quotes must be escaped, but we just disallow those
        let drop_q = format!("DROP DATABASE \"{}\"", self.name);
        let res = match admin_conn.execute(drop_q.as_str()).await {
            Ok(_) => Ok(true),
            Err(SqlxError::Database(db_err)) if db_err.code() == Some(Cow::Borrowed("3D000")) => {
                // invalid catalog name is raised if the database does not exist
                Ok(false)
            }
            Err(err) => Err(err_msg!(Backend, "Error removing database").with_cause(err)),
        }?;
        admin_conn.close().await?;
        Ok(res)
    }
}

impl<'a> ManageBackend<'a> for PostgresStoreOptions {
    type Backend = PostgresBackend;

    fn open_backend(
        self,
        method: Option<StoreKeyMethod>,
        pass_key: PassKey<'_>,
        profile: Option<String>,
    ) -> BoxFuture<'a, Result<PostgresBackend, Error>> {
        let pass_key = pass_key.into_owned();
        Box::pin(self.open(method, pass_key, profile))
    }

    fn provision_backend(
        self,
        method: StoreKeyMethod,
        pass_key: PassKey<'_>,
        profile: Option<String>,
        recreate: bool,
    ) -> BoxFuture<'a, Result<PostgresBackend, Error>> {
        let pass_key = pass_key.into_owned();
        Box::pin(self.provision(method, pass_key, profile, recreate))
    }

    fn remove_backend(self) -> BoxFuture<'a, Result<bool, Error>> {
        Box::pin(self.remove())
    }
}

pub(crate) async fn init_db(
    mut txn: Transaction<'_, Postgres>,
    profile_name: &str,
    store_key_ref: String,
    enc_profile_key: Vec<u8>,
    schema: &str,
) -> Result<ProfileId, Error> {
    txn.execute(
        format!(r#"
        CREATE SCHEMA IF NOT EXISTS "{schema}";

        CREATE TABLE "{schema}".config (
            name TEXT NOT NULL,
            value TEXT,
            PRIMARY KEY(name)
        );

        CREATE TABLE "{schema}".profiles (
            id BIGSERIAL,
            name TEXT NOT NULL,
            reference TEXT NULL,
            profile_key BYTEA NULL,
            PRIMARY KEY(id)
        );
        CREATE UNIQUE INDEX ix_profile_name ON "{schema}".profiles(name);

        CREATE TABLE "{schema}".items (
            id BIGSERIAL,
            profile_id BIGINT NOT NULL,
            kind SMALLINT NOT NULL,
            category BYTEA NOT NULL,
            name BYTEA NOT NULL,
            value BYTEA NOT NULL,
            expiry TIMESTAMP NULL,
            PRIMARY KEY(id),
            FOREIGN KEY(profile_id) REFERENCES "{schema}".profiles(id)
                ON DELETE CASCADE ON UPDATE CASCADE
        );
        CREATE UNIQUE INDEX ix_items_uniq ON "{schema}".items(profile_id, kind, category, name);

        CREATE TABLE "{schema}".items_tags (
            id BIGSERIAL,
            item_id BIGINT NOT NULL,
            name BYTEA NOT NULL,
            value BYTEA NOT NULL,
            plaintext SMALLINT NOT NULL,
            PRIMARY KEY(id),
            FOREIGN KEY(item_id) REFERENCES "{schema}".items(id)
                ON DELETE CASCADE ON UPDATE CASCADE
        );
        CREATE INDEX ix_items_tags_item_id ON "{schema}".items_tags(item_id);
        CREATE INDEX ix_items_tags_name_enc ON "{schema}".items_tags(name, SUBSTR(value, 1, 12)) INCLUDE (item_id) WHERE plaintext=0;
        CREATE INDEX ix_items_tags_name_plain ON "{schema}".items_tags(name, value) INCLUDE (item_id) WHERE plaintext=1;
    "#).as_str(),
    )
    .await
    .map_err(err_map!(Backend, "Error creating database tables"))?;

    sqlx::query(
        "INSERT INTO config (name, value) VALUES
            ('default_profile', $1),
            ('key', $2),
            ('version', '1')",
    )
    .persistent(false)
    .bind(profile_name)
    .bind(store_key_ref)
    .execute(txn.as_mut())
    .await
    .map_err(err_map!(Backend, "Error inserting configuration"))?;

    let profile_id =
        sqlx::query_scalar("INSERT INTO profiles (name, profile_key) VALUES ($1, $2) RETURNING id")
            .bind(profile_name)
            .bind(enc_profile_key)
            .fetch_one(txn.as_mut())
            .await
            .map_err(err_map!(Backend, "Error inserting default profile"))?;

    txn.commit().await?;

    Ok(profile_id)
}

pub(crate) async fn reset_db(conn: &mut PgConnection) -> Result<(), Error> {
    conn.execute(
        "
        DROP TABLE IF EXISTS
          config, profiles,
          profile_keys, keys,
          items, items_tags;
        ",
    )
    .await?;
    Ok(())
}

pub(crate) async fn open_db(
    conn_pool: PgPool,
    method: Option<StoreKeyMethod>,
    pass_key: PassKey<'_>,
    profile: Option<String>,
    host: String,
    name: String,
) -> Result<PostgresBackend, Error> {
    let mut conn = conn_pool.acquire().await?;
    let mut ver_ok = false;
    let mut default_profile: Option<String> = None;
    let mut store_key_ref: Option<String> = None;

    let config = sqlx::query(
        r#"SELECT name, value FROM config
        WHERE name IN ('default_profile', 'key', 'version')"#,
    )
    .fetch_all(conn.as_mut())
    .await
    .map_err(err_map!(Backend, "Error fetching store configuration"))?;
    for row in config {
        match row.try_get(0)? {
            "default_profile" => {
                default_profile.replace(row.try_get(1)?);
            }
            "key" => {
                store_key_ref.replace(row.try_get(1)?);
            }
            "version" => {
                if row.try_get::<&str, _>(1)? != "1" {
                    return Err(err_msg!(Unsupported, "Unsupported store version"));
                }
                ver_ok = true;
            }
            _ => (),
        }
    }
    if !ver_ok {
        return Err(err_msg!(Unsupported, "Store version not found"));
    }
    let profile = profile
        .or(default_profile)
        .ok_or_else(|| err_msg!(Unsupported, "Default store profile not found"))?;
    let store_key = if let Some(store_key_ref) = store_key_ref {
        let wrap_ref = StoreKeyReference::parse_uri(&store_key_ref)?;
        if let Some(method) = method {
            if !wrap_ref.compare_method(&method) {
                return Err(err_msg!(Input, "Store key method mismatch"));
            }
        }
        unblock({
            let pass_key = pass_key.into_owned();
            move || wrap_ref.resolve(pass_key)
        })
        .await?
    } else {
        return Err(err_msg!(Unsupported, "Store key not found"));
    };

    let mut key_cache = KeyCache::new(store_key);
    let row = sqlx::query("SELECT id, profile_key FROM profiles WHERE name = $1")
        .bind(&profile)
        .fetch_one(conn.as_mut())
        .await?;
    let profile_id = row.try_get(0)?;
    let profile_key = key_cache.load_key(row.try_get(1)?).await?;
    conn.return_to_pool().await;

    key_cache.add_profile_mut(profile.clone(), profile_id, profile_key);

    Ok(PostgresBackend::new(
        conn_pool, profile, key_cache, host, name,
    ))
}

/// Validate a postgres identifier.
/// Any character except NUL is allowed in an identifier. Double quotes must be escaped,
/// but we just disallow those instead.
fn _validate_ident(ident: &str, name: &str) -> Result<(), Error> {
    if ident.is_empty() {
        Err(err_msg!(Input, "{name} identifier is empty"))
    } else if ident.find(['"', '\0']).is_some() {
        Err(err_msg!(
            Input,
            "Invalid character in {name} identifier: '\"' and '\\0' are disallowed"
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_parse_uri() {
        let uri = "postgres://user:pass@host/db_name\
            ?admin_account=user2&admin_password=pass2\
            &connect_timeout=9&max_connections=23&min_connections=32\
            &idle_timeout=99\
            &test=1";
        let opts = PostgresStoreOptions::new(uri).unwrap();
        assert_eq!(opts.max_connections, 23);
        assert_eq!(opts.min_connections, 32);
        assert_eq!(opts.connect_timeout, Duration::from_secs(9));
        assert_eq!(opts.idle_timeout, Duration::from_secs(99));
        assert_eq!(opts.uri, "postgres://user:pass@host/db_name?test=1");
        assert_eq!(
            opts.admin_uri,
            "postgres://user2:pass2@host/postgres?test=1"
        );
    }
}
