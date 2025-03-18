//! Generic backend support

use std::{fmt::Debug, sync::Arc};

use super::{Backend, BackendSession, ManageBackend};
use crate::{
    backend::OrderBy,
    entry::{Entry, EntryKind, EntryOperation, EntryTag, Scan, TagFilter},
    error::Error,
    future::BoxFuture,
    options::IntoOptions,
    protect::{PassKey, StoreKeyMethod},
};

#[cfg(feature = "postgres")]
use super::postgres;

#[cfg(feature = "sqlite")]
use super::sqlite;

/// A dynamic store backend instance
#[derive(Clone, Debug)]
pub struct AnyBackend(Arc<dyn Backend<Session = AnyBackendSession>>);

/// Wrap a backend instance into an AnyBackend
pub fn into_any_backend(inst: impl Backend + 'static) -> AnyBackend {
    AnyBackend(Arc::new(WrapBackend(inst)))
}

/// This structure turns a generic backend into a concrete type
#[derive(Debug)]
struct WrapBackend<B: Backend>(B);

impl<B: Backend> Backend for WrapBackend<B> {
    type Session = AnyBackendSession;

    #[inline]
    fn create_profile(&self, name: Option<String>) -> BoxFuture<'_, Result<String, Error>> {
        self.0.create_profile(name)
    }

    #[inline]
    fn get_active_profile(&self) -> String {
        self.0.get_active_profile()
    }

    #[inline]
    fn get_default_profile(&self) -> BoxFuture<'_, Result<String, Error>> {
        self.0.get_default_profile()
    }

    #[inline]
    fn set_default_profile(&self, profile: String) -> BoxFuture<'_, Result<(), Error>> {
        self.0.set_default_profile(profile)
    }

    #[inline]
    fn list_profiles(&self) -> BoxFuture<'_, Result<Vec<String>, Error>> {
        self.0.list_profiles()
    }

    #[inline]
    fn remove_profile(&self, name: String) -> BoxFuture<'_, Result<bool, Error>> {
        self.0.remove_profile(name)
    }

    #[inline]
    fn rename_profile(
        &self,
        from_name: String,
        to_name: String,
    ) -> BoxFuture<'_, Result<bool, Error>> {
        self.0.rename_profile(from_name, to_name)
    }

    #[inline]
    fn scan(
        &self,
        profile: Option<String>,
        kind: Option<EntryKind>,
        category: Option<String>,
        tag_filter: Option<TagFilter>,
        offset: Option<i64>,
        limit: Option<i64>,
        order_by: Option<OrderBy>,
        descending: bool,
    ) -> BoxFuture<'_, Result<Scan<'static, Entry>, Error>> {
        self.0.scan(
            profile, kind, category, tag_filter, offset, limit, order_by, descending,
        )
    }

    #[inline]
    fn session(&self, profile: Option<String>, transaction: bool) -> Result<Self::Session, Error> {
        Ok(AnyBackendSession(Box::new(
            self.0.session(profile, transaction)?,
        )))
    }

    #[inline]
    fn rekey(
        &mut self,
        method: StoreKeyMethod,
        key: PassKey<'_>,
    ) -> BoxFuture<'_, Result<(), Error>> {
        self.0.rekey(method, key)
    }

    #[inline]
    fn close(&self) -> BoxFuture<'_, Result<(), Error>> {
        self.0.close()
    }
}

// Forward to the concrete inner backend instance
impl Backend for AnyBackend {
    type Session = AnyBackendSession;

    #[inline]
    fn create_profile(&self, name: Option<String>) -> BoxFuture<'_, Result<String, Error>> {
        self.0.create_profile(name)
    }

    #[inline]
    fn get_active_profile(&self) -> String {
        self.0.get_active_profile()
    }

    #[inline]
    fn get_default_profile(&self) -> BoxFuture<'_, Result<String, Error>> {
        self.0.get_default_profile()
    }

    #[inline]
    fn set_default_profile(&self, profile: String) -> BoxFuture<'_, Result<(), Error>> {
        self.0.set_default_profile(profile)
    }

    #[inline]
    fn list_profiles(&self) -> BoxFuture<'_, Result<Vec<String>, Error>> {
        self.0.list_profiles()
    }

    #[inline]
    fn remove_profile(&self, name: String) -> BoxFuture<'_, Result<bool, Error>> {
        self.0.remove_profile(name)
    }

    #[inline]
    fn rename_profile(
        &self,
        from_name: String,
        to_name: String,
    ) -> BoxFuture<'_, Result<bool, Error>> {
        self.0.rename_profile(from_name, to_name)
    }

    #[inline]
    fn scan(
        &self,
        profile: Option<String>,
        kind: Option<EntryKind>,
        category: Option<String>,
        tag_filter: Option<TagFilter>,
        offset: Option<i64>,
        limit: Option<i64>,
        order_by: Option<OrderBy>,
        descending: bool,
    ) -> BoxFuture<'_, Result<Scan<'static, Entry>, Error>> {
        self.0.scan(
            profile, kind, category, tag_filter, offset, limit, order_by, descending,
        )
    }

    #[inline]
    fn session(&self, profile: Option<String>, transaction: bool) -> Result<Self::Session, Error> {
        Ok(AnyBackendSession(Box::new(
            self.0.session(profile, transaction)?,
        )))
    }

    #[inline]
    fn rekey(
        &mut self,
        method: StoreKeyMethod,
        key: PassKey<'_>,
    ) -> BoxFuture<'_, Result<(), Error>> {
        match Arc::get_mut(&mut self.0) {
            Some(inner) => inner.rekey(method, key),
            None => Box::pin(std::future::ready(Err(err_msg!(
                "Cannot re-key a store with multiple references"
            )))),
        }
    }

    #[inline]
    fn close(&self) -> BoxFuture<'_, Result<(), Error>> {
        self.0.close()
    }
}

/// A dynamic store session instance
#[derive(Debug)]
pub struct AnyBackendSession(Box<dyn BackendSession>);

impl BackendSession for AnyBackendSession {
    /// Count the number of matching records in the store
    fn count<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>> {
        self.0.count(kind, category, tag_filter)
    }

    /// Fetch a single record from the store by category and name
    fn fetch<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        name: &'q str,
        for_update: bool,
    ) -> BoxFuture<'q, Result<Option<Entry>, Error>> {
        self.0.fetch(kind, category, name, for_update)
    }

    /// Fetch all matching records from the store
    fn fetch_all<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
        limit: Option<i64>,
        order_by: Option<OrderBy>,
        descending: bool,
        for_update: bool,
    ) -> BoxFuture<'q, Result<Vec<Entry>, Error>> {
        self.0.fetch_all(
            kind, category, tag_filter, limit, order_by, descending, for_update,
        )
    }

    /// Remove all matching records from the store
    fn remove_all<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>> {
        self.0.remove_all(kind, category, tag_filter)
    }

    /// Insert or replace a record in the store
    #[allow(clippy::too_many_arguments)]
    fn update<'q>(
        &'q mut self,
        kind: EntryKind,
        operation: EntryOperation,
        category: &'q str,
        name: &'q str,
        value: Option<&'q [u8]>,
        tags: Option<&'q [EntryTag]>,
        expiry_ms: Option<i64>,
    ) -> BoxFuture<'q, Result<(), Error>> {
        self.0
            .update(kind, operation, category, name, value, tags, expiry_ms)
    }

    /// Test the connection to the store
    fn ping(&mut self) -> BoxFuture<'_, Result<(), Error>> {
        self.0.ping()
    }

    /// Close the current store session
    fn close(&mut self, commit: bool) -> BoxFuture<'_, Result<(), Error>> {
        self.0.close(commit)
    }
}

impl<'a> ManageBackend<'a> for &'a str {
    type Backend = AnyBackend;

    fn open_backend(
        self,
        method: Option<StoreKeyMethod>,
        pass_key: PassKey<'a>,
        profile: Option<String>,
    ) -> BoxFuture<'a, Result<Self::Backend, Error>> {
        Box::pin(async move {
            let opts = self.into_options()?;
            debug!("Open store with options: {:?}", &opts);

            match opts.scheme.as_ref() {
                #[cfg(feature = "postgres")]
                "postgres" => {
                    let opts = postgres::PostgresStoreOptions::new(opts)?;
                    let mgr = opts.open(method, pass_key, profile).await?;
                    Ok(into_any_backend(mgr))
                }

                #[cfg(feature = "sqlite")]
                "sqlite" => {
                    let opts = sqlite::SqliteStoreOptions::new(opts)?;
                    let mgr = opts.open(method, pass_key, profile).await?;
                    Ok(into_any_backend(mgr))
                }

                _ => Err(err_msg!(
                    Unsupported,
                    "Unsupported backend: {}",
                    &opts.scheme
                )),
            }
        })
    }

    fn provision_backend(
        self,
        method: StoreKeyMethod,
        pass_key: PassKey<'a>,
        profile: Option<String>,
        recreate: bool,
    ) -> BoxFuture<'a, Result<Self::Backend, Error>> {
        Box::pin(async move {
            let opts = self.into_options()?;
            debug!("Provision store with options: {:?}", &opts);

            match opts.scheme.as_ref() {
                #[cfg(feature = "postgres")]
                "postgres" => {
                    let opts = postgres::PostgresStoreOptions::new(opts)?;
                    let mgr = opts.provision(method, pass_key, profile, recreate).await?;
                    Ok(into_any_backend(mgr))
                }

                #[cfg(feature = "sqlite")]
                "sqlite" => {
                    let opts = sqlite::SqliteStoreOptions::new(opts)?;
                    let mgr = opts.provision(method, pass_key, profile, recreate).await?;
                    Ok(into_any_backend(mgr))
                }

                _ => Err(err_msg!(
                    Unsupported,
                    "Unsupported backend: {}",
                    &opts.scheme
                )),
            }
        })
    }

    fn remove_backend(self) -> BoxFuture<'a, Result<bool, Error>> {
        Box::pin(async move {
            let opts = self.into_options()?;
            debug!("Remove store with options: {:?}", &opts);

            match opts.scheme.as_ref() {
                #[cfg(feature = "postgres")]
                "postgres" => {
                    let opts = postgres::PostgresStoreOptions::new(opts)?;
                    Ok(opts.remove().await?)
                }

                #[cfg(feature = "sqlite")]
                "sqlite" => {
                    let opts = sqlite::SqliteStoreOptions::new(opts)?;
                    Ok(opts.remove().await?)
                }

                _ => Err(err_msg!(
                    Unsupported,
                    "Unsupported backend: {}",
                    &opts.scheme
                )),
            }
        })
    }
}
