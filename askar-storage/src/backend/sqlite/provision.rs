use std::{
    borrow::Cow, fs::remove_file, io::ErrorKind as IoErrorKind, str::FromStr,
    thread::available_parallelism, time::Duration,
};

use sqlx::{
    sqlite::{
        SqliteAutoVacuum, SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqlitePool,
        SqlitePoolOptions, SqliteSynchronous,
    },
    ConnectOptions, Error as SqlxError, Row,
};

use super::SqliteBackend;
use crate::{
    backend::{
        db_utils::{init_keys, random_profile_name},
        ManageBackend,
    },
    error::Error,
    future::{sleep, unblock, BoxFuture},
    options::{IntoOptions, Options},
    protect::{KeyCache, PassKey, StoreKeyMethod, StoreKeyReference},
};

const DEFAULT_MIN_CONNECTIONS: usize = 1;
const DEFAULT_LOWER_MAX_CONNECTIONS: usize = 4;
const DEFAULT_UPPER_MAX_CONNECTIONS: usize = 8;
const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_JOURNAL_MODE: SqliteJournalMode = SqliteJournalMode::Wal;
const DEFAULT_LOCKING_MODE: SqliteLockingMode = SqliteLockingMode::Normal;
const DEFAULT_SYNCHRONOUS: SqliteSynchronous = SqliteSynchronous::Full;

/// Configuration options for Sqlite stores
#[derive(Debug)]
pub struct SqliteStoreOptions {
    pub(crate) in_memory: bool,
    pub(crate) path: String,
    pub(crate) busy_timeout: Duration,
    pub(crate) max_connections: u32,
    pub(crate) min_connections: u32,
    pub(crate) journal_mode: SqliteJournalMode,
    pub(crate) locking_mode: SqliteLockingMode,
    pub(crate) shared_cache: bool,
    pub(crate) synchronous: SqliteSynchronous,
}

impl Default for SqliteStoreOptions {
    fn default() -> Self {
        Self::new(":memory:").expect("Error initializing with default options")
    }
}

impl SqliteStoreOptions {
    /// Initialize `SqliteStoreOptions` from a generic set of options
    pub fn new<'a>(options: impl IntoOptions<'a>) -> Result<Self, Error> {
        let mut opts = options.into_options()?;
        let mut path = opts.host.to_string();
        path.push_str(&opts.path);
        let in_memory = path == ":memory:";

        let busy_timeout = if let Some(timeout) = opts.query.remove("busy_timeout") {
            Duration::from_millis(
                timeout
                    .parse()
                    .map_err(err_map!(Input, "Error parsing 'busy_timeout' parameter"))?,
            )
        } else {
            DEFAULT_BUSY_TIMEOUT
        };
        let max_connections = if let Some(max_conn) = opts.query.remove("max_connections") {
            max_conn
                .parse()
                .map_err(err_map!(Input, "Error parsing 'max_connections' parameter"))?
        } else {
            #[allow(clippy::manual_clamp)]
            {
                available_parallelism()
                    .map_err(err_map!(
                        Unexpected,
                        "Error determining available parallelism"
                    ))?
                    .get()
                    .max(DEFAULT_LOWER_MAX_CONNECTIONS)
                    .min(DEFAULT_UPPER_MAX_CONNECTIONS) as u32
            }
        };
        let min_connections = if let Some(min_conn) = opts.query.remove("min_connections") {
            min_conn
                .parse()
                .map_err(err_map!(Input, "Error parsing 'min_connections' parameter"))?
        } else {
            DEFAULT_MIN_CONNECTIONS as u32
        };
        let journal_mode = if let Some(mode) = opts.query.remove("journal_mode") {
            SqliteJournalMode::from_str(&mode)
                .map_err(err_map!(Input, "Error parsing 'journal_mode' parameter"))?
        } else {
            DEFAULT_JOURNAL_MODE
        };
        let locking_mode = if let Some(mode) = opts.query.remove("locking_mode") {
            SqliteLockingMode::from_str(&mode)
                .map_err(err_map!(Input, "Error parsing 'locking_mode' parameter"))?
        } else {
            DEFAULT_LOCKING_MODE
        };
        let shared_cache = if let Some(cache) = opts.query.remove("cache") {
            cache.eq_ignore_ascii_case("shared")
        } else {
            in_memory
        };
        let synchronous = if let Some(sync) = opts.query.remove("synchronous") {
            SqliteSynchronous::from_str(&sync)
                .map_err(err_map!(Input, "Error parsing 'synchronous' parameter"))?
        } else {
            DEFAULT_SYNCHRONOUS
        };

        Ok(Self {
            in_memory,
            path,
            busy_timeout,
            max_connections,
            min_connections,
            journal_mode,
            locking_mode,
            shared_cache,
            synchronous,
        })
    }

    async fn pool(&self, auto_create: bool) -> std::result::Result<SqlitePool, SqlxError> {
        #[allow(unused_mut)]
        let mut conn_opts = SqliteConnectOptions::from_str(self.path.as_ref())?
            .create_if_missing(auto_create)
            .auto_vacuum(SqliteAutoVacuum::Incremental)
            .busy_timeout(self.busy_timeout)
            .journal_mode(self.journal_mode)
            .locking_mode(self.locking_mode)
            .shared_cache(self.shared_cache)
            .synchronous(self.synchronous);
        #[cfg(feature = "log")]
        {
            conn_opts = conn_opts
                .log_statements(log::LevelFilter::Debug)
                .log_slow_statements(log::LevelFilter::Debug, Default::default());
        }
        SqlitePoolOptions::default()
            // maintains at least 1 connection.
            // for an in-memory database this is required to avoid dropping the database,
            // for a file database this signals other instances that the database is in use
            .min_connections(self.min_connections)
            .max_connections(self.max_connections)
            .test_before_acquire(false)
            .connect_with(conn_opts)
            .await
    }

    /// Provision a new Sqlite store from these configuration options
    pub async fn provision(
        self,
        method: StoreKeyMethod,
        pass_key: PassKey<'_>,
        profile: Option<String>,
        recreate: bool,
    ) -> Result<SqliteBackend, Error> {
        if recreate && !self.in_memory {
            try_remove_file(self.path.to_string()).await?;
        }
        let conn_pool = self
            .pool(true)
            .await
            .map_err(err_map!(Backend, "Error creating database pool"))?;

        if !recreate {
            let mut conn = conn_pool.acquire().await?;
            let found = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='config'",
            )
            .fetch_one(conn.as_mut())
            .await
            .map_err(err_map!(Backend, "Error checking for existing store"))?
                == 1;
            conn.return_to_pool().await;
            if found {
                return open_db(
                    conn_pool,
                    Some(method),
                    pass_key,
                    profile,
                    self.path.to_string(),
                )
                .await;
            }
        }
        // else: no 'config' table, assume empty database

        let default_profile = profile.unwrap_or_else(random_profile_name);
        let key_cache = init_db(&conn_pool, &default_profile, method, pass_key).await?;

        Ok(SqliteBackend::new(
            conn_pool,
            default_profile,
            key_cache,
            self.path.to_string(),
        ))
    }

    /// Open an existing Sqlite store from this set of configuration options
    pub async fn open(
        self,
        method: Option<StoreKeyMethod>,
        pass_key: PassKey<'_>,
        profile: Option<String>,
    ) -> Result<SqliteBackend, Error> {
        let conn_pool = match self.pool(false).await {
            Ok(pool) => Ok(pool),
            Err(SqlxError::Database(db_err)) => {
                if db_err.code().expect("Expected SQLite error code") == "14" {
                    // SQLITE_CANTOPEN error
                    Err(err_msg!(
                        NotFound,
                        "The requested database path was not found"
                    ))
                } else {
                    Err(err_msg!(Backend, "Error connecting to database pool")
                        .with_cause(SqlxError::Database(db_err)))
                }
            }
            Err(err) => Err(err.into()),
        }?;
        open_db(conn_pool, method, pass_key, profile, self.path.to_string()).await
    }

    /// Remove the Sqlite store defined by these configuration options
    pub async fn remove(self) -> Result<bool, Error> {
        if self.in_memory {
            Ok(true)
        } else {
            try_remove_file(self.path.to_string()).await
        }
    }

    /// Default options for an in-memory Sqlite store
    pub fn in_memory() -> Self {
        Self::from_path(":memory:")
    }

    /// Default options for a given Sqlite database path
    pub fn from_path(path: &str) -> Self {
        let opts = Options {
            host: Cow::Borrowed(path),
            ..Default::default()
        };
        Self::new(opts).unwrap()
    }
}

impl<'a> ManageBackend<'a> for SqliteStoreOptions {
    type Backend = SqliteBackend;

    fn open_backend(
        self,
        method: Option<StoreKeyMethod>,
        pass_key: PassKey<'a>,
        profile: Option<String>,
    ) -> BoxFuture<'a, Result<SqliteBackend, Error>> {
        Box::pin(self.open(method, pass_key, profile))
    }

    fn provision_backend(
        self,
        method: StoreKeyMethod,
        pass_key: PassKey<'a>,
        profile: Option<String>,
        recreate: bool,
    ) -> BoxFuture<'a, Result<SqliteBackend, Error>> {
        Box::pin(self.provision(method, pass_key, profile, recreate))
    }

    fn remove_backend(self) -> BoxFuture<'a, Result<bool, Error>> {
        Box::pin(self.remove())
    }
}

async fn init_db(
    conn_pool: &SqlitePool,
    profile_name: &str,
    method: StoreKeyMethod,
    pass_key: PassKey<'_>,
) -> Result<KeyCache, Error> {
    let (profile_key, enc_profile_key, store_key, store_key_ref) = unblock({
        let pass_key = pass_key.into_owned();
        move || init_keys(method, pass_key)
    })
    .await?;

    let mut conn = conn_pool.acquire().await?;

    sqlx::query(
        r#"
        BEGIN EXCLUSIVE TRANSACTION;

        CREATE TABLE config (
            name TEXT NOT NULL,
            value TEXT,
            PRIMARY KEY (name)
        );
        INSERT INTO config (name, value) VALUES
            ("default_profile", ?1),
            ("key", ?2),
            ("version", "1");

        CREATE TABLE profiles (
            id INTEGER NOT NULL,
            name TEXT NOT NULL,
            reference TEXT NULL,
            profile_key BLOB NULL,
            PRIMARY KEY(id)
        );
        CREATE UNIQUE INDEX ix_profile_name ON profiles (name);

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
        CREATE UNIQUE INDEX ix_items_uniq ON items (profile_id, kind, category, name);

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
        CREATE INDEX ix_items_tags_name_enc ON items_tags (name, SUBSTR(value, 1, 12)) WHERE plaintext=0;
        CREATE INDEX ix_items_tags_name_plain ON items_tags (name, value) WHERE plaintext=1;

        INSERT INTO profiles (name, profile_key) VALUES (?1, ?3);

        COMMIT;
    "#,
    )
    .persistent(false)
    .bind(profile_name)
    .bind(store_key_ref)
    .bind(enc_profile_key)
    .execute(conn.as_mut())
    .await.map_err(err_map!(Backend, "Error creating database tables"))?;

    let row = sqlx::query("SELECT id FROM profiles WHERE name = ?1")
        .persistent(false)
        .bind(profile_name)
        .fetch_one(conn.as_mut())
        .await
        .map_err(err_map!(Backend, "Error checking for existing profile"))?;
    conn.return_to_pool().await;

    let mut key_cache = KeyCache::new(store_key);
    key_cache.add_profile_mut(profile_name.to_string(), row.try_get(0)?, profile_key);

    Ok(key_cache)
}

async fn open_db(
    conn_pool: SqlitePool,
    method: Option<StoreKeyMethod>,
    pass_key: PassKey<'_>,
    profile: Option<String>,
    path: String,
) -> Result<SqliteBackend, Error> {
    let mut conn = conn_pool.acquire().await?;
    let mut ver_ok = false;
    let mut default_profile: Option<String> = None;
    let mut store_key_ref: Option<String> = None;

    let config = sqlx::query(
        r#"SELECT name, value FROM config
        WHERE name IN ("default_profile", "key", "version")"#,
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
    let row = sqlx::query("SELECT id, profile_key FROM profiles WHERE name = ?1")
        .bind(&profile)
        .fetch_one(conn.as_mut())
        .await?;
    let profile_id = row.try_get(0)?;
    let profile_key = key_cache.load_key(row.try_get(1)?).await?;
    conn.return_to_pool().await;
    key_cache.add_profile_mut(profile.clone(), profile_id, profile_key);

    Ok(SqliteBackend::new(conn_pool, profile, key_cache, path))
}

async fn try_remove_file(path: String) -> Result<bool, Error> {
    let mut retries = 0;
    loop {
        let path = path.clone();
        if let Some(res) = unblock(move || match remove_file(path) {
            Ok(()) => Ok(Some(true)),
            Err(err) if err.kind() == IoErrorKind::NotFound => Ok(Some(false)),
            #[cfg(target_os = "windows")]
            // database file in use: it seems that in current versions, sqlx may return from close()
            // before all connections to the database have been closed.
            Err(err) if err.raw_os_error() == Some(32) => Ok(None),
            Err(err) => Err(err_msg!(Backend, "Error removing file").with_cause(err)),
        })
        .await?
        {
            break Ok(res);
        } else {
            sleep(Duration::from_millis(50)).await;
            retries += 1;
            if retries >= 10 {
                return Err(err_msg!(Backend, "Error removing file: still in use"));
            }
        }
    }
}
