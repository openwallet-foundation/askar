//! Storage backends supported by aries-askar

use std::fmt::Debug;

use crate::{
    entry::{Entry, EntryKind, EntryOperation, EntryTag, Scan, TagFilter},
    error::{Error, ErrorKind},
    future::BoxFuture,
    protect::{PassKey, StoreKeyMethod},
};

#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) mod db_utils;

#[cfg(feature = "postgres")]
#[cfg_attr(docsrs, doc(cfg(feature = "postgres")))]
/// Postgres database support
pub mod postgres;

#[cfg(feature = "sqlite")]
#[cfg_attr(docsrs, doc(cfg(feature = "sqlite")))]
/// Sqlite database support
pub mod sqlite;

/// Enum to support custom ordering in record queries
#[derive(Debug, Default)]
pub enum OrderBy {
    /// Order by ID field
    #[default]
    Id,
}

/// Represents a generic backend implementation
pub trait Backend: Debug + Send + Sync {
    /// The type of session managed by this backend
    type Session: BackendSession + 'static;

    /// Create a new profile
    fn create_profile(&self, name: Option<String>) -> BoxFuture<'_, Result<String, Error>>;

    /// Get the name of the active profile
    fn get_active_profile(&self) -> String;

    /// Get the name of the default profile
    fn get_default_profile(&self) -> BoxFuture<'_, Result<String, Error>>;

    /// Set the the default profile
    fn set_default_profile(&self, profile: String) -> BoxFuture<'_, Result<(), Error>>;

    /// Get the details of all store profiles
    fn list_profiles(&self) -> BoxFuture<'_, Result<Vec<String>, Error>>;

    /// Remove an existing profile
    fn remove_profile(&self, name: String) -> BoxFuture<'_, Result<bool, Error>>;

    /// Create a [`Scan`] against the store
    #[allow(clippy::too_many_arguments)]
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
    ) -> BoxFuture<'_, Result<Scan<'static, Entry>, Error>>;

    /// Create a new session against the store
    fn session(&self, profile: Option<String>, transaction: bool) -> Result<Self::Session, Error>;

    /// Replace the wrapping key of the store
    fn rekey(
        &mut self,
        method: StoreKeyMethod,
        key: PassKey<'_>,
    ) -> BoxFuture<'_, Result<(), Error>>;

    /// Close the store instance
    fn close(&self) -> BoxFuture<'_, Result<(), Error>>;
}

/// Create, open, or remove a generic backend implementation
pub trait ManageBackend<'a> {
    /// The type of backend being managed
    type Backend: Backend;

    /// Open an existing store
    fn open_backend(
        self,
        method: Option<StoreKeyMethod>,
        pass_key: PassKey<'a>,
        profile: Option<String>,
    ) -> BoxFuture<'a, Result<Self::Backend, Error>>;

    /// Provision a new store
    fn provision_backend(
        self,
        method: StoreKeyMethod,
        pass_key: PassKey<'a>,
        profile: Option<String>,
        recreate: bool,
    ) -> BoxFuture<'a, Result<Self::Backend, Error>>;

    /// Remove an existing store
    fn remove_backend(self) -> BoxFuture<'a, Result<bool, Error>>;
}

/// Query from a generic backend implementation
pub trait BackendSession: Debug + Send {
    /// Count the number of matching records in the store
    fn count<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>>;

    /// Fetch a single record from the store by category and name
    fn fetch<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        name: &'q str,
        for_update: bool,
    ) -> BoxFuture<'q, Result<Option<Entry>, Error>>;

    /// Fetch all matching records from the store
    #[allow(clippy::too_many_arguments)]
    fn fetch_all<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
        limit: Option<i64>,
        order_by: Option<OrderBy>,
        descending: bool,
        for_update: bool,
    ) -> BoxFuture<'q, Result<Vec<Entry>, Error>>;

    /// Insert scan results from another profile or store
    fn import_scan<'q>(
        &'q mut self,
        mut scan: Scan<'q, Entry>,
    ) -> BoxFuture<'q, Result<(), Error>> {
        Box::pin(async move {
            while let Some(rows) = scan.fetch_next().await? {
                for entry in rows {
                    self.update(
                        entry.kind,
                        EntryOperation::Insert,
                        entry.category.as_str(),
                        entry.name.as_str(),
                        Some(entry.value.as_ref()),
                        Some(entry.tags.as_ref()),
                        None,
                    )
                    .await?;
                }
            }
            Ok(())
        })
    }

    /// Remove all matching records from the store
    fn remove_all<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>>;

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
    ) -> BoxFuture<'q, Result<(), Error>>;

    /// Test the connection to the store
    fn ping(&mut self) -> BoxFuture<'_, Result<(), Error>>;

    /// Close the current store session
    fn close(&mut self, commit: bool) -> BoxFuture<'_, Result<(), Error>>;
}

/// Insert all records from a given profile
pub async fn copy_profile<A: Backend, B: Backend>(
    from_backend: &A,
    to_backend: &B,
    from_profile: &str,
    to_profile: &str,
) -> Result<(), Error> {
    let scan = from_backend
        .scan(
            Some(from_profile.into()),
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .await?;
    if let Err(e) = to_backend.create_profile(Some(to_profile.into())).await {
        if e.kind() != ErrorKind::Duplicate {
            return Err(e);
        }
    }
    let mut txn = to_backend.session(Some(to_profile.into()), true)?;
    let count = txn.count(None, None, None).await?;
    if count > 0 {
        return Err(err_msg!(Input, "Profile targeted for import is not empty"));
    }
    txn.import_scan(scan).await?;
    txn.close(true).await?;
    Ok(())
}

/// Export an entire Store to another location
pub async fn copy_store<'m, B: Backend, M: ManageBackend<'m>>(
    source: &B,
    target: M,
    key_method: StoreKeyMethod,
    pass_key: PassKey<'m>,
    recreate: bool,
) -> Result<<M as ManageBackend<'m>>::Backend, Error> {
    let default_profile = source.get_default_profile().await?;
    let profile_ids = source.list_profiles().await?;
    let target = target
        .provision_backend(key_method, pass_key, Some(default_profile), recreate)
        .await?;
    for profile in profile_ids {
        copy_profile(source, &target, &profile, &profile).await?;
    }
    Ok(target)
}
