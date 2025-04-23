//! Store wrapper for running tests against a postgres database

use sqlx::{
    postgres::{PgConnection, Postgres},
    Connection, Database, TransactionManager,
};
use std::time::Duration;

use super::provision::{init_db, reset_db, PostgresStoreOptions};
use super::PostgresBackend;
use crate::{
    any::{into_any_backend, AnyBackend},
    backend::{
        db_utils::{init_keys, random_profile_name},
        Backend,
    },
    error::Error,
    future::{sleep, spawn_ok, timeout, unblock},
    protect::{generate_raw_store_key, KeyCache, StoreKeyMethod},
};

#[derive(Debug)]
/// Postgres test database wrapper instance
pub struct TestDB {
    inst: Option<AnyBackend>,
    lock_txn: Option<PgConnection>,
}

impl TestDB {
    /// Access the backend instance
    pub fn backend(&self) -> AnyBackend {
        self.inst.clone().expect("Database not opened")
    }

    /// Provision a new instance of the test database.
    /// This method blocks until the database lock can be acquired.
    pub async fn provision(db_url: &str) -> Result<TestDB, Error> {
        let key = generate_raw_store_key(None)?;
        let (profile_key, enc_profile_key, store_key, store_key_ref) =
            unblock(|| init_keys(StoreKeyMethod::RawKey, key)).await?;
        let default_profile = random_profile_name();

        let opts = PostgresStoreOptions::new(db_url)?;
        let conn_pool = opts.create_db_pool().await?;

        // we hold a transaction open with a fixed advisory lock value.
        // this will block until any existing TestDB instance is dropped
        let lock_txn = loop {
            // acquire a new connection free from the pool. this is to ensure that
            // connections are being closed, in case postgres is near the
            // configured connection limit.
            let mut lock_txn = conn_pool.acquire().await?.detach();
            <Postgres as Database>::TransactionManager::begin(&mut lock_txn, None).await?;
            if sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(99999)")
                .fetch_one(&mut lock_txn)
                .await?
            {
                break lock_txn;
            }
            lock_txn.close().await?;
            sleep(Duration::from_millis(50)).await;
        };

        let mut init_txn = conn_pool.begin().await?;
        // delete existing tables
        reset_db(&mut init_txn).await?;

        // create tables and add default profile
        let profile_id = init_db(
            init_txn,
            &default_profile,
            store_key_ref,
            enc_profile_key,
            &opts.username,
        )
        .await?;

        let mut key_cache = KeyCache::new(store_key);
        key_cache.add_profile_mut(default_profile.clone(), profile_id, profile_key);
        let inst = into_any_backend(PostgresBackend::new(
            conn_pool,
            default_profile,
            key_cache,
            opts.host,
            opts.name,
        ));

        Ok(TestDB {
            inst: Some(inst),
            lock_txn: Some(lock_txn),
        })
    }

    async fn close_internal(
        mut lock_txn: Option<PgConnection>,
        mut inst: Option<AnyBackend>,
    ) -> Result<(), Error> {
        if let Some(lock_txn) = lock_txn.take() {
            if let Err(e) = lock_txn.close().await {
                warn!("Error closing lock transaction: {}", e);
            }
        }
        if let Some(inst) = inst.take() {
            timeout(Duration::from_secs(30), inst.close())
                .await
                .ok_or_else(|| {
                    err_msg!(
                        Backend,
                        "Timed out waiting for the pool connection to close"
                    )
                })??;
        }
        Ok(())
    }

    /// Explicitly close the test database
    pub async fn close(mut self) -> Result<(), Error> {
        Self::close_internal(self.lock_txn.take(), self.inst.take()).await?;
        Ok(())
    }
}

impl Drop for TestDB {
    fn drop(&mut self) {
        if self.lock_txn.is_some() || self.inst.is_some() {
            let lock_txn = self.lock_txn.take();
            let inst = self.inst.take();
            spawn_ok(async {
                Self::close_internal(lock_txn, inst)
                    .await
                    .expect("Error closing database connection");
            });
        }
    }
}
