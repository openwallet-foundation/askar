use std::{collections::BTreeMap, ffi::CString, os::raw::c_char, ptr, str::FromStr, sync::Arc};

use askar_storage::backend::{copy_profile, OrderBy};
use async_lock::{Mutex as TryMutex, MutexGuardArc as TryMutexGuard, RwLock};
use ffi_support::{rust_string_to_c, ByteBuffer, FfiStr};
use once_cell::sync::Lazy;

use super::{
    error::set_last_error,
    key::LocalKeyHandle,
    result_list::{
        EntryListHandle, FfiEntryList, FfiKeyEntryList, KeyEntryListHandle, StringListHandle,
    },
    tags::EntryTagSet,
    CallbackId, EnsureCallback, ErrorCode, ResourceHandle,
};
use crate::{
    entry::{Entry, EntryOperation, Scan, TagFilter},
    error::Error,
    ffi::result_list::FfiStringList,
    future::spawn_ok,
    kms::KeyReference,
    store::{PassKey, Session, Store, StoreKeyMethod},
};

new_sequence_handle!(StoreHandle, FFI_STORE_COUNTER);
new_sequence_handle!(SessionHandle, FFI_SESSION_COUNTER);
new_sequence_handle!(ScanHandle, FFI_SCAN_COUNTER);

static FFI_STORES: Lazy<RwLock<BTreeMap<StoreHandle, Store>>> =
    Lazy::new(|| RwLock::new(BTreeMap::new()));
static FFI_SESSIONS: Lazy<StoreResourceMap<SessionHandle, Session>> =
    Lazy::new(StoreResourceMap::new);
static FFI_SCANS: Lazy<StoreResourceMap<ScanHandle, Scan<'static, Entry>>> =
    Lazy::new(StoreResourceMap::new);

impl StoreHandle {
    pub async fn create(value: Store) -> Self {
        let handle = Self::next();
        let mut repo = FFI_STORES.write().await;
        repo.insert(handle, value);
        handle
    }

    pub async fn load(&self) -> Result<Store, Error> {
        FFI_STORES
            .read()
            .await
            .get(self)
            .cloned()
            .ok_or_else(|| err_msg!("Invalid store handle"))
    }

    pub async fn remove(&self) -> Result<Store, Error> {
        FFI_STORES
            .write()
            .await
            .remove(self)
            .ok_or_else(|| err_msg!("Invalid store handle"))
    }

    pub async fn replace(&self, store: Store) {
        FFI_STORES.write().await.insert(*self, store);
    }
}

struct StoreResourceMap<K, V> {
    #[allow(clippy::type_complexity)]
    map: RwLock<BTreeMap<K, (StoreHandle, Arc<TryMutex<V>>)>>,
}

impl<K, V> StoreResourceMap<K, V>
where
    K: ResourceHandle,
{
    pub fn new() -> Self {
        Self {
            map: RwLock::new(BTreeMap::new()),
        }
    }

    pub async fn insert(&self, store: StoreHandle, value: V) -> K {
        let handle = K::next();
        let mut map = self.map.write().await;
        map.insert(handle, (store, Arc::new(TryMutex::new(value))));
        handle
    }

    pub async fn remove(&self, handle: K) -> Option<Result<V, Error>> {
        self.map.write().await.remove(&handle).map(|(_s, v)| {
            Arc::try_unwrap(v)
                .map(|item| item.into_inner())
                .map_err(|_| err_msg!(Busy, "Resource handle in use"))
        })
    }

    pub async fn borrow(&self, handle: K) -> Result<TryMutexGuard<V>, Error> {
        Ok(self
            .map
            .read()
            .await
            .get(&handle)
            .ok_or_else(|| err_msg!("Invalid resource handle"))?
            .1
            .lock_arc()
            .await)
    }

    pub async fn remove_all(&self, store: StoreHandle) -> Result<(), Error> {
        let mut guard = self.map.write().await;
        let mut pos = K::from(0usize);
        let mut found;
        loop {
            found = false;
            for (h, (sh, _)) in guard.range(pos..) {
                if store == *sh {
                    pos = *h;
                    found = true;
                    break;
                }
            }
            if found {
                guard.remove(&pos);
            } else {
                break;
            }
        }
        Ok(())
    }
}

#[no_mangle]
pub extern "C" fn askar_store_generate_raw_key(
    seed: ByteBuffer,
    out: *mut *const c_char,
) -> ErrorCode {
    catch_err! {
        trace!("Create raw store key");
        let seed = match seed.as_slice() {
            &[] => None,
            s => Some(s)
        };
        let key = Store::new_raw_key(seed)?;
        unsafe { *out = rust_string_to_c(key.to_string()); }
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_provision(
    spec_uri: FfiStr<'_>,
    key_method: FfiStr<'_>,
    pass_key: FfiStr<'_>,
    profile: FfiStr<'_>,
    recreate: i8,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, handle: StoreHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Provision store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let spec_uri = spec_uri.into_opt_string().ok_or_else(|| err_msg!("No provision spec URI provided"))?;
        let key_method = match key_method.as_opt_str() {
            Some(method) => StoreKeyMethod::parse_uri(method)?,
            None => StoreKeyMethod::default()
        };
        let pass_key = PassKey::from(pass_key.as_opt_str()).into_owned();
        let profile = profile.into_opt_string();
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(sid) => {
                    debug!("Provisioned store {}", sid);
                    cb(cb_id, ErrorCode::Success, sid)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err)), StoreHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = Store::provision(
                    spec_uri.as_str(),
                    key_method,
                    pass_key,
                    profile,
                    recreate != 0
                ).await?;
                Ok(StoreHandle::create(store).await)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_open(
    spec_uri: FfiStr<'_>,
    key_method: FfiStr<'_>,
    pass_key: FfiStr<'_>,
    profile: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, handle: StoreHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Open store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let spec_uri = spec_uri.into_opt_string().ok_or_else(|| err_msg!("No store URI provided"))?;
        let key_method = match key_method.as_opt_str() {
            Some(method) => Some(StoreKeyMethod::parse_uri(method)?),
            None => None
        };
        let pass_key = PassKey::from(pass_key.as_opt_str()).into_owned();
        let profile = profile.into_opt_string();
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(sid) => {
                    debug!("Opened store {}", sid);
                    cb(cb_id, ErrorCode::Success, sid)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err)), StoreHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = Store::open (
                spec_uri.as_str(),
                    key_method,
                    pass_key,
                    profile
                ).await?;
                Ok(StoreHandle::create(store).await)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_remove(
    spec_uri: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, i8)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Remove store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let spec_uri = spec_uri.into_opt_string().ok_or_else(|| err_msg!("No store URI provided"))?;
        let cb = EnsureCallback::new(move |result: Result<bool,Error>|
            match result {
                Ok(removed) => cb(cb_id, ErrorCode::Success, removed as i8),
                Err(err) => cb(cb_id, set_last_error(Some(err)), 0),
            }
        );
        spawn_ok(async move {
            let result = Store::remove(spec_uri.as_str()).await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_create_profile(
    handle: StoreHandle,
    profile: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, result_p: *const c_char)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Create profile");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let profile = profile.into_opt_string();
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(name) => cb(cb_id, ErrorCode::Success, rust_string_to_c(name)),
                Err(err) => cb(cb_id, set_last_error(Some(err)), ptr::null()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                let name = store.create_profile(profile).await?;
                Ok(name)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_get_profile_name(
    handle: StoreHandle,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, name: *const c_char)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Get profile name");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(name) => cb(cb_id, ErrorCode::Success, rust_string_to_c(name)),
                Err(err) => cb(cb_id, set_last_error(Some(err)), ptr::null_mut()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                Ok(store.get_active_profile())
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_list_profiles(
    handle: StoreHandle,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, results: StringListHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("List profiles");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(rows) => {
                    let res = StringListHandle::create(FfiStringList::from(rows));
                    cb(cb_id, ErrorCode::Success, res)
                },
                Err(err) => cb(cb_id, set_last_error(Some(err)), StringListHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                let rows = store.list_profiles().await?;
                Ok(rows)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_remove_profile(
    handle: StoreHandle,
    profile: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, removed: i8)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Remove profile");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let profile = profile.into_opt_string().ok_or_else(|| err_msg!("Profile name not provided"))?;
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(removed) => cb(cb_id, ErrorCode::Success, removed as i8),
                Err(err) => cb(cb_id, set_last_error(Some(err)), 0),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                store.remove_profile(profile).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_get_default_profile(
    handle: StoreHandle,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, profile: *const c_char)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Get default profile");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let cb = EnsureCallback::new(move |result: Result<String, Error>|
            match result {
                Ok(name) => cb(cb_id, ErrorCode::Success,
                    CString::new(name.as_str()).unwrap().into_raw() as *const c_char),
                Err(err) => cb(cb_id, set_last_error(Some(err)), ptr::null()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                store.get_default_profile().await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_set_default_profile(
    handle: StoreHandle,
    profile: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Set default profile");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let profile = profile.into_opt_string().ok_or_else(|| err_msg!("Profile name not provided"))?;
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(_) => cb(cb_id, ErrorCode::Success),
                Err(err) => cb(cb_id, set_last_error(Some(err))),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                store.set_default_profile(profile).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_rekey(
    handle: StoreHandle,
    key_method: FfiStr<'_>,
    pass_key: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Re-key store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let key_method = match key_method.as_opt_str() {
            Some(method) => StoreKeyMethod::parse_uri(method)?,
            None => StoreKeyMethod::default()
        };
        let pass_key = PassKey::from(pass_key.as_opt_str()).into_owned();
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(_) => cb(cb_id, ErrorCode::Success),
                Err(err) => cb(cb_id, set_last_error(Some(err))),
            }
        );
        spawn_ok(async move {
            let result = async {
                let mut store = handle.remove().await?;
                let result = store.rekey(key_method, pass_key.as_ref()).await;
                handle.replace(store).await;
                result
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_copy(
    handle: StoreHandle,
    target_uri: FfiStr<'_>,
    key_method: FfiStr<'_>,
    pass_key: FfiStr<'_>,
    recreate: i8,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, handle: StoreHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Copy store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let target_uri = target_uri.into_opt_string().ok_or_else(|| err_msg!("No target URI provided"))?;
        let key_method = match key_method.as_opt_str() {
            Some(method) => StoreKeyMethod::parse_uri(method)?,
            None => StoreKeyMethod::default()
        };
        let pass_key = PassKey::from(pass_key.as_opt_str()).into_owned();
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(handle) => cb(cb_id, ErrorCode::Success, handle),
                Err(err) => cb(cb_id, set_last_error(Some(err)), StoreHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async move {
                let store = handle.load().await?;
                let copied = store.copy_to(target_uri.as_str(), key_method, pass_key.as_ref(), recreate != 0).await?;
                debug!("Copied store {}", handle);
                Ok(StoreHandle::create(copied).await)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_copy_profile(
    from_handle: StoreHandle,
    to_handle: StoreHandle,
    from_profile: FfiStr<'_>,
    to_profile: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Copy profile");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let from_profile = from_profile.into_opt_string().ok_or_else(|| err_msg!("Profile name not provided"))?;
        let to_profile = to_profile.into_opt_string().unwrap_or_else(|| from_profile.clone());
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(()) => cb(cb_id, ErrorCode::Success),
                Err(err) => cb(cb_id, set_last_error(Some(err))),
            }
        );
        spawn_ok(async move {
            let result = async move {
                let from_store = from_handle.load().await?;
                let to_store = to_handle.load().await?;
                copy_profile(from_store.backend(), to_store.backend(), &from_profile, &to_profile).await?;
                debug!("Copied profile {}/{} to {}/{}", from_handle, from_profile, to_handle, to_profile);
                Ok(())
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_close(
    handle: StoreHandle,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Close store");
        let cb = cb.map(|cb| {
            EnsureCallback::new(move |result|
                match result {
                    Ok(_) => cb(cb_id, ErrorCode::Success),
                    Err(err) => cb(cb_id, set_last_error(Some(err))),
                }
            )
        });
        spawn_ok(async move {
            let result = async {
                let store = handle.remove().await?;
                // remove any leftover sessions and scans associated with this store,
                // to avoid blocking unnecessarily due to handles that simply haven't
                // been dropped yet (this will invalidate associated handles)
                FFI_SESSIONS.remove_all(handle).await?;
                FFI_SCANS.remove_all(handle).await?;
                store.close().await?;
                debug!("Closed store {}", handle);
                Ok(())
            }.await;
            if let Some(cb) = cb {
                cb.resolve(result);
            }
            else if let Err(err) = result {
                error!("{}", err);
            }
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_scan_start(
    handle: StoreHandle,
    profile: FfiStr<'_>,
    category: FfiStr<'_>,
    tag_filter: FfiStr<'_>,
    offset: i64,
    limit: i64,
    order_by: FfiStr<'_>,
    descending: i8,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, handle: ScanHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    let order_by_str = order_by.as_opt_str().map(|s| s.to_lowercase());
    let order_by = match order_by_str.as_deref() {
        Some("id") => Some(OrderBy::Id),
        Some(_) => return ErrorCode::Unsupported,
        None => None,
    };
    let descending = descending != 0; // Convert to bool

    catch_err! {
        trace!("Scan store start");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let profile = profile.into_opt_string();
        let category = category.into_opt_string();
        let tag_filter = tag_filter.as_opt_str().map(TagFilter::from_str).transpose()?;
        let cb = EnsureCallback::new(move |result: Result<ScanHandle,Error>|
            match result {
                Ok(scan_handle) => {
                    debug!("Started scan {} on store {}", scan_handle, handle);
                    cb(cb_id, ErrorCode::Success, scan_handle)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err)), ScanHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                let scan = store.scan(profile, category, tag_filter, Some(offset), if limit < 0 { None }else {Some(limit)}, order_by, descending).await?;
                Ok(FFI_SCANS.insert(handle, scan).await)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_scan_next(
    handle: ScanHandle,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, results: EntryListHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Scan store next");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let cb = EnsureCallback::new(move |result: Result<Option<Vec<Entry>>,Error>|
            match result {
                Ok(Some(entries)) => {
                    let results = EntryListHandle::create(FfiEntryList::from(entries));
                    cb(cb_id, ErrorCode::Success, results)
                },
                Ok(None) => cb(cb_id, ErrorCode::Success, EntryListHandle::invalid()),
                Err(err) => cb(cb_id, set_last_error(Some(err)), EntryListHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let mut scan = FFI_SCANS.borrow(handle).await?;
                let entries = scan.fetch_next().await?;
                Ok(entries)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_scan_free(handle: ScanHandle) -> ErrorCode {
    catch_err! {
        trace!("Close scan");
        spawn_ok(async move {
            // the Scan may have been removed due to the Store being closed
            if let Some(scan) = FFI_SCANS.remove(handle).await {
                scan.ok();
                debug!("Closed scan {}", handle);
            } else {
                debug!("Scan not found for closing: {}", handle);
            }
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_start(
    handle: StoreHandle,
    profile: FfiStr<'_>,
    as_transaction: i8,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, handle: SessionHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Session start");
        let profile = profile.into_opt_string();
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let cb = EnsureCallback::new(move |result: Result<SessionHandle,Error>|
            match result {
                Ok(sess_handle) => {
                    debug!("Started session {} on store {} (txn: {})", sess_handle, handle, as_transaction != 0);
                    cb(cb_id, ErrorCode::Success, sess_handle)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err)), SessionHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                let session = if as_transaction == 0 {
                    store.session(profile).await?
                } else {
                    store.transaction(profile).await?
                };
                Ok(FFI_SESSIONS.insert(handle, session).await)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_count(
    handle: SessionHandle,
    category: FfiStr<'_>,
    tag_filter: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, count: i64)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Count from store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let category = category.into_opt_string();
        let tag_filter = tag_filter.as_opt_str().map(TagFilter::from_str).transpose()?;
        let cb = EnsureCallback::new(move |result: Result<i64,Error>|
            match result {
                Ok(count) => cb(cb_id, ErrorCode::Success, count),
                Err(err) => cb(cb_id, set_last_error(Some(err)), 0),
            }
        );
        spawn_ok(async move {
            let result = async {
                let mut session = FFI_SESSIONS.borrow(handle).await?;
                session.count(category.as_deref(), tag_filter).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_fetch(
    handle: SessionHandle,
    category: FfiStr<'_>,
    name: FfiStr<'_>,
    for_update: i8,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, results: EntryListHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Fetch from store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let category = category.into_opt_string().ok_or_else(|| err_msg!("Category not provided"))?;
        let name = name.into_opt_string().ok_or_else(|| err_msg!("Name not provided"))?;
        let cb = EnsureCallback::new(move |result: Result<Option<Entry>,Error>|
            match result {
                Ok(Some(entry)) => {
                    let results = EntryListHandle::create(FfiEntryList::from(entry));
                    cb(cb_id, ErrorCode::Success, results)
                },
                Ok(None) => cb(cb_id, ErrorCode::Success, EntryListHandle::invalid()),
                Err(err) => cb(cb_id, set_last_error(Some(err)), EntryListHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let mut session = FFI_SESSIONS.borrow(handle).await?;
                session.fetch(&category, &name, for_update != 0).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_fetch_all(
    handle: SessionHandle,
    category: FfiStr<'_>,
    tag_filter: FfiStr<'_>,
    limit: i64,
    order_by: FfiStr<'_>,
    descending: i8,
    for_update: i8,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, results: EntryListHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    let order_by_str = order_by.as_opt_str().map(|s| s.to_lowercase());
    let order_by = match order_by_str.as_deref() {
        Some("id") => Some(OrderBy::Id),
        Some(_) => return ErrorCode::Unsupported,
        None => None,
    };
    let descending = descending != 0; // Convert to bool

    catch_err! {
        trace!("Count from store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let category = category.into_opt_string();
        let tag_filter = tag_filter.as_opt_str().map(TagFilter::from_str).transpose()?;
        let limit = if limit < 0 { None } else {Some(limit)};
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(rows) => {
                    let results = EntryListHandle::create(FfiEntryList::from(rows));
                    cb(cb_id, ErrorCode::Success, results)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err)), EntryListHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let mut session = FFI_SESSIONS.borrow(handle).await?;
                session.fetch_all(category.as_deref(), tag_filter, limit, order_by, descending, for_update != 0).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_remove_all(
    handle: SessionHandle,
    category: FfiStr<'_>,
    tag_filter: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, removed: i64)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Count from store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let category = category.into_opt_string();
        let tag_filter = tag_filter.as_opt_str().map(TagFilter::from_str).transpose()?;
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(removed) => {
                    cb(cb_id, ErrorCode::Success, removed)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err)), 0),
            }
        );
        spawn_ok(async move {
            let result = async {
                let mut session = FFI_SESSIONS.borrow(handle).await?;
                session.remove_all(category.as_deref(), tag_filter).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_update(
    handle: SessionHandle,
    operation: i8,
    category: FfiStr<'_>,
    name: FfiStr<'_>,
    value: ByteBuffer,
    tags: FfiStr<'_>,
    expiry_ms: i64,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Update store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let operation = match operation {
            0 => EntryOperation::Insert,
            1 => EntryOperation::Replace,
            2 => EntryOperation::Remove,
            _ => return Err(err_msg!("Invalid update operation"))
        };
        let category = category.into_opt_string().ok_or_else(|| err_msg!("Entry category not provided"))?;
        let name = name.into_opt_string().ok_or_else(|| err_msg!("Entry name not provided"))?;
        let value = value.as_slice().to_vec();
        let tags = if let Some(tags) = tags.as_opt_str() {
            Some(
                serde_json::from_str::<EntryTagSet<'static>>(tags)
                    .map_err(err_map!("Error decoding tags"))?
                    .into_vec(),
            )
        } else {
            None
        };
        let expiry_ms = if expiry_ms < 0 {
            None
        } else {
            Some(expiry_ms)
        };
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(_) => cb(cb_id, ErrorCode::Success),
                Err(err) => cb(cb_id, set_last_error(Some(err))),
            }
        );
        spawn_ok(async move {
            let result = async {
                let mut session = FFI_SESSIONS.borrow(handle).await?;
                session.update(operation, &category, &name, Some(value.as_slice()), tags.as_deref(), expiry_ms).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_insert_key(
    handle: SessionHandle,
    key_handle: LocalKeyHandle,
    name: FfiStr<'_>,
    metadata: FfiStr<'_>,
    tags: FfiStr<'_>,
    expiry_ms: i64,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Insert key");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let key = key_handle.load()?;
        let name = name.into_opt_string().ok_or_else(|| err_msg!("No key name provided"))?;
        let metadata = metadata.into_opt_string();
        let tags = if let Some(tags) = tags.as_opt_str() {
            Some(
                serde_json::from_str::<EntryTagSet<'static>>(tags)
                    .map_err(err_map!("Error decoding tags"))?
                    .into_vec(),
            )
        } else {
            None
        };
        let expiry_ms = if expiry_ms < 0 {
            None
        } else {
            Some(expiry_ms)
        };
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(_) => {
                    cb(cb_id, ErrorCode::Success)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err))),
            }
        );

        let reference = key.is_hardware_backed().then_some(KeyReference::MobileSecureElement);

        spawn_ok(async move {
            let result = async {
                let mut session = FFI_SESSIONS.borrow(handle).await?;
                session.insert_key(
                    name.as_str(),
                    &key,
                    metadata.as_deref(),
                    reference,
                    tags.as_deref(),
                    expiry_ms,
                ).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_fetch_key(
    handle: SessionHandle,
    name: FfiStr<'_>,
    for_update: i8,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, results: KeyEntryListHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Fetch key");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let name = name.into_opt_string().ok_or_else(|| err_msg!("No key name provided"))?;

        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(Some(entry)) => {
                    let results = KeyEntryListHandle::create(FfiKeyEntryList::from(entry));
                    cb(cb_id, ErrorCode::Success, results)
                }
                Ok(None) => {
                    cb(cb_id, ErrorCode::Success, KeyEntryListHandle::invalid())
                }
                Err(err) => cb(cb_id, set_last_error(Some(err)), KeyEntryListHandle::invalid()),
            }
        );

        spawn_ok(async move {
            let result = async {
                let mut session = FFI_SESSIONS.borrow(handle).await?;
                session.fetch_key(
                    name.as_str(),
                    for_update != 0
                ).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_fetch_all_keys(
    handle: SessionHandle,
    alg: FfiStr<'_>,
    thumbprint: FfiStr<'_>,
    tag_filter: FfiStr<'_>,
    limit: i64,
    for_update: i8,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, results: KeyEntryListHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Fetch all keys");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let alg = alg.into_opt_string();
        let thumbprint = thumbprint.into_opt_string();
        let tag_filter = tag_filter.as_opt_str().map(TagFilter::from_str).transpose()?;
        let limit = if limit < 0 { None } else {Some(limit)};

        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(entries) => {
                    let results = KeyEntryListHandle::create(FfiKeyEntryList::from(entries));
                    cb(cb_id, ErrorCode::Success, results)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err)), KeyEntryListHandle::invalid()),
            }
        );

        spawn_ok(async move {
            let result = async {
                let mut session = FFI_SESSIONS.borrow(handle).await?;
                session.fetch_all_keys(
                    alg.as_deref(),
                    thumbprint.as_deref(),
                    tag_filter,
                    limit,
                    for_update != 0
                ).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_update_key(
    handle: SessionHandle,
    name: FfiStr<'_>,
    metadata: FfiStr<'_>,
    tags: FfiStr<'_>,
    expiry_ms: i64,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Update key");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let name = name.into_opt_string().ok_or_else(|| err_msg!("No key name provided"))?;
        let metadata = metadata.into_opt_string();
        let tags = if let Some(tags) = tags.as_opt_str() {
            Some(
                serde_json::from_str::<EntryTagSet<'static>>(tags)
                    .map_err(err_map!("Error decoding tags"))?
                    .into_vec(),
            )
        } else {
            None
        };
        let expiry_ms = if expiry_ms < 0 {
            None
        } else {
            Some(expiry_ms)
        };
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(_) => {
                    cb(cb_id, ErrorCode::Success)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err))),
            }
        );

        spawn_ok(async move {
            let result = async {
                let mut session = FFI_SESSIONS.borrow(handle).await?;
                session.update_key(
                    &name,
                    metadata.as_deref(),
                    tags.as_deref(),
                    expiry_ms,

                ).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_remove_key(
    handle: SessionHandle,
    name: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Remove key");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let name = name.into_opt_string().ok_or_else(|| err_msg!("No key name provided"))?;
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(_) => {
                    cb(cb_id, ErrorCode::Success)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err))),
            }
        );

        spawn_ok(async move {
            let result = async {
                let mut session = FFI_SESSIONS.borrow(handle).await?;
                session.remove_key(
                    &name,
                ).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_close(
    handle: SessionHandle,
    commit: i8,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Close session");
        let cb = cb.map(|cb| {
            EnsureCallback::new(move |result|
                match result {
                    Ok(_) => cb(cb_id, ErrorCode::Success),
                    Err(err) => {
                        cb(cb_id, set_last_error(Some(err)))
                    }
                }
            )
        });
        spawn_ok(async move {
            let result = async {
                // the Session may have been removed due to the Store being closed
                if let Some(session) = FFI_SESSIONS.remove(handle).await {
                    let session = session?;
                    if commit == 0 {
                        // not necessary - rollback is automatic for txn,
                        // and for regular session there is no action to perform
                        // > session.rollback().await?;
                    } else {
                        session.commit().await?;
                    }
                    debug!("Closed session {}", handle);
                } else {
                    debug!("Session not found for closing: {}", handle);
                }
                Ok(())
            }.await;
            if let Some(cb) = cb {
                cb.resolve(result);
            }
            else if let Err(err) = result {
                error!("{}", err);
            }
        });
        Ok(ErrorCode::Success)
    }
}
