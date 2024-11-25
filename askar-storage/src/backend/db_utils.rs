use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use sqlx::{
    pool::PoolConnection, Arguments, Database, Encode, Error as SqlxError, IntoArguments, Pool,
    TransactionManager, Type,
};

use crate::{
    entry::{EncEntryTag, Entry, EntryKind, EntryTag, TagFilter},
    error::Error,
    future::BoxFuture,
    protect::{EntryEncryptor, KeyCache, PassKey, ProfileId, ProfileKey, StoreKey, StoreKeyMethod},
    wql::{
        sql::TagSqlEncoder,
        tags::{tag_query, TagQueryEncoder},
    },
};

use super::OrderBy;

/// cbindgen:ignore
pub const PAGE_SIZE: usize = 32;

pub type Expiry = chrono::DateTime<chrono::Utc>;

pub(crate) type Connection<DB> = <DB as Database>::Connection;

#[derive(Debug)]
pub(crate) enum DbSessionState<DB: ExtDatabase> {
    Active { conn: PoolConnection<DB> },
    Pending { pool: Pool<DB>, transaction: bool },
    Closed,
}

unsafe impl<DB: ExtDatabase> Sync for DbSessionState<DB> where DB::Connection: Send {}

#[derive(Debug)]
pub struct DbSession<DB: ExtDatabase> {
    profile_key: DbSessionKey,
    state: DbSessionState<DB>,
    txn_depth: usize,
}

impl<DB: ExtDatabase> DbSession<DB> {
    pub(crate) fn new(
        pool: Pool<DB>,
        cache: Arc<KeyCache>,
        profile: String,
        transaction: bool,
    ) -> Self
    where
        DB: Database,
    {
        Self {
            profile_key: DbSessionKey::Pending { cache, profile },
            state: DbSessionState::Pending { pool, transaction },
            txn_depth: 0,
        }
    }

    #[inline]
    fn connection_mut(&mut self) -> Option<&mut PoolConnection<DB>> {
        if let DbSessionState::Active { conn } = &mut self.state {
            Some(conn)
        } else {
            None
        }
    }

    #[inline]
    pub fn in_transaction(&self) -> bool {
        if self.txn_depth > 0 {
            return true;
        }
        if let DbSessionState::Pending {
            transaction: true, ..
        } = &self.state
        {
            return true;
        }
        false
    }

    pub(crate) fn profile_and_key(&mut self) -> Option<(ProfileId, Arc<ProfileKey>)> {
        if let DbSessionKey::Active {
            profile_id,
            ref key,
        } = self.profile_key
        {
            Some((profile_id, key.clone()))
        } else {
            None
        }
    }

    pub(crate) async fn make_active<I>(
        &mut self,
        init_key: I,
    ) -> Result<DbSessionActive<'_, DB>, Error>
    where
        I: for<'a> GetProfileKey<'a, DB>,
    {
        if let DbSessionState::Pending { pool, transaction } = &self.state {
            debug!("Acquire pool connection");
            let mut conn = pool
                .acquire()
                .await
                .map_err(err_map!(Backend, "Error acquiring pool connection"))?;
            if *transaction {
                debug!("Start transaction");
                DB::start_transaction(&mut conn, false)
                    .await
                    .map_err(err_map!(Backend, "Error starting transaction"))?;
                self.txn_depth += 1;
            }
            self.state = DbSessionState::Active { conn };
        }
        let profile_id = match &mut self.profile_key {
            DbSessionKey::Pending { cache, profile } => {
                let cache = cache.clone();
                let mut get_profile = String::new();
                std::mem::swap(profile, &mut get_profile);
                let in_txn = self.in_transaction();
                let (profile_id, key) = init_key
                    .call_once(self.connection_mut().unwrap(), cache, get_profile, in_txn)
                    .await?;
                self.profile_key = DbSessionKey::Active { profile_id, key };
                profile_id
            }
            DbSessionKey::Active { profile_id, .. } => *profile_id,
        };
        Ok(DbSessionActive {
            inner: self,
            profile_id,
        })
    }

    #[inline]
    pub(crate) fn borrow_mut(&mut self) -> DbSessionRef<'_, DB> {
        DbSessionRef::Borrowed(self)
    }

    #[inline]
    pub(crate) fn owned_ref(self) -> DbSessionRef<'static, DB> {
        DbSessionRef::Owned(self)
    }

    pub(crate) async fn close(&mut self, commit: bool) -> Result<(), Error> {
        let state = std::mem::replace(&mut self.state, DbSessionState::Closed);
        if self.txn_depth > 0 {
            self.txn_depth = 0;
            if let DbSessionState::Active { mut conn, .. } = state {
                if commit {
                    debug!("Commit transaction on close");
                    DB::TransactionManager::commit(&mut conn).await
                } else {
                    debug!("Roll-back transaction on close");
                    DB::TransactionManager::rollback(&mut conn).await
                }
                .map_err(err_map!(Backend, "Error closing transaction"))?;
                conn.return_to_pool().await;
            } else {
                warn!("Could not close out transaction: session not active");
            }
        }
        Ok(())
    }
}

impl<DB: ExtDatabase> Drop for DbSession<DB> {
    fn drop(&mut self) {
        if self.txn_depth > 0 {
            self.txn_depth = 0;
            if let Some(conn) = self.connection_mut() {
                debug!("Dropped transaction: roll-back");
                DB::TransactionManager::start_rollback(conn);
            }
        } else {
            debug!("Dropped pool connection")
        }
    }
}

pub(crate) trait GetProfileKey<'a, DB: Database> {
    type Fut: Future<Output = Result<(ProfileId, Arc<ProfileKey>), Error>>;
    fn call_once(
        self,
        conn: &'a mut PoolConnection<DB>,
        cache: Arc<KeyCache>,
        profile: String,
        in_txn: bool,
    ) -> Self::Fut;
}

impl<'a, DB: Database, F, Fut> GetProfileKey<'a, DB> for F
where
    F: FnOnce(&'a mut PoolConnection<DB>, Arc<KeyCache>, String, bool) -> Fut,
    Fut: Future<Output = Result<(ProfileId, Arc<ProfileKey>), Error>> + 'a,
{
    type Fut = Fut;
    fn call_once(
        self,
        conn: &'a mut PoolConnection<DB>,
        cache: Arc<KeyCache>,
        profile: String,
        in_txn: bool,
    ) -> Self::Fut {
        self(conn, cache, profile, in_txn)
    }
}

#[derive(Debug)]
pub(crate) enum DbSessionKey {
    Active {
        profile_id: ProfileId,
        key: Arc<ProfileKey>,
    },
    Pending {
        cache: Arc<KeyCache>,
        profile: String,
    },
}

pub trait ExtDatabase: Database {
    fn start_transaction(
        conn: &mut Connection<Self>,
        _nested: bool,
    ) -> BoxFuture<'_, Result<(), SqlxError>> {
        <Self as Database>::TransactionManager::begin(conn)
    }
}

pub enum DbSessionRef<'q, DB: ExtDatabase> {
    Owned(DbSession<DB>),
    Borrowed(&'q mut DbSession<DB>),
}

impl<DB: ExtDatabase> DbSessionRef<'_, DB> {
    pub fn is_owned(&self) -> bool {
        matches!(self, Self::Owned(_))
    }
}

impl<'q, DB: ExtDatabase> Deref for DbSessionRef<'q, DB> {
    type Target = DbSession<DB>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(e) => e,
            Self::Borrowed(e) => e,
        }
    }
}

impl<'q, DB: ExtDatabase> DerefMut for DbSessionRef<'q, DB> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Owned(e) => e,
            Self::Borrowed(e) => e,
        }
    }
}

pub(crate) struct DbSessionActive<'a, DB: ExtDatabase> {
    inner: &'a mut DbSession<DB>,
    pub(crate) profile_id: ProfileId,
}

impl<'q, DB: ExtDatabase> DbSessionActive<'q, DB> {
    #[inline]
    pub fn connection_mut(&mut self) -> &mut Connection<DB> {
        self.inner
            .connection_mut()
            .expect("Tried to fetch connection from closed session")
            .as_mut()
    }

    #[allow(unused)]
    pub fn in_transaction(&self) -> bool {
        self.inner.in_transaction()
    }

    #[allow(unused)]
    pub async fn begin<'t>(&'t mut self) -> Result<DbSessionTxn<'t, DB>, Error>
    where
        'q: 't,
    {
        debug!("Start nested transaction");
        DB::start_transaction(self.connection_mut(), true)
            .await
            .map_err(err_map!(Backend, "Error starting nested transaction"))?;
        self.inner.txn_depth += 1;
        Ok(DbSessionTxn {
            inner: &mut *self.inner,
            profile_id: self.profile_id,
            rollback: true,
        })
    }

    pub async fn as_transaction<'t>(&'t mut self) -> Result<DbSessionTxn<'t, DB>, Error>
    where
        'q: 't,
    {
        if self.inner.txn_depth == 0 {
            debug!("Start transaction");
            DB::start_transaction(self.connection_mut(), false)
                .await
                .map_err(err_map!(Backend, "Error starting transaction"))?;
            self.inner.txn_depth += 1;
            Ok(DbSessionTxn {
                inner: &mut *self.inner,
                profile_id: self.profile_id,
                rollback: true,
            })
        } else {
            Ok(DbSessionTxn {
                inner: &mut *self.inner,
                profile_id: self.profile_id,
                rollback: false,
            })
        }
    }
}

pub(crate) struct DbSessionTxn<'a, DB: ExtDatabase> {
    inner: &'a mut DbSession<DB>,
    pub(crate) profile_id: ProfileId,
    rollback: bool,
}

impl<'a, DB: ExtDatabase> DbSessionTxn<'a, DB> {
    pub fn connection_mut(&mut self) -> &mut Connection<DB> {
        self.inner.connection_mut().unwrap().as_mut()
    }

    pub async fn commit(mut self) -> Result<(), Error> {
        if self.rollback {
            self.rollback = false;
            self.inner.txn_depth -= 1;
            let conn = self.connection_mut();
            debug!("Commit transaction");
            DB::TransactionManager::commit(conn)
                .await
                .map_err(err_map!(Backend, "Error committing transaction"))?;
        }
        Ok(())
    }
}

impl<'a, DB: ExtDatabase> Drop for DbSessionTxn<'a, DB> {
    fn drop(&mut self) {
        if self.rollback {
            self.inner.txn_depth -= 1;
            debug!("Roll-back dropped nested transaction");
            DB::TransactionManager::start_rollback(self.connection_mut());
        }
    }
}

pub(crate) trait RunInTransaction<'a, 'q: 'a, DB: ExtDatabase> {
    type Fut: Future<Output = Result<(), Error>>;
    fn call_once(self, conn: &'a mut DbSessionActive<'q, DB>) -> Self::Fut;
}

impl<'a, 'q: 'a, DB: ExtDatabase, F, Fut> RunInTransaction<'a, 'q, DB> for F
where
    F: FnOnce(&'a mut DbSessionActive<'q, DB>) -> Fut,
    Fut: Future<Output = Result<(), Error>> + 'a,
{
    type Fut = Fut;
    fn call_once(self, conn: &'a mut DbSessionActive<'q, DB>) -> Self::Fut {
        self(conn)
    }
}

pub struct EncScanEntry {
    pub kind: EntryKind,
    pub category: Vec<u8>,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub tags: Vec<u8>,
}

pub struct QueryParams<'q, DB: Database> {
    args: DB::Arguments<'q>,
    count: usize,
}

impl<'q, DB: Database> QueryParams<'q, DB> {
    pub fn new() -> Self {
        Self {
            args: Default::default(),
            count: 0,
        }
    }

    pub fn extend<I, T>(&mut self, vals: I)
    where
        I: IntoIterator<Item = T>,
        T: 'q + Send + sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    {
        for item in vals {
            self.args.add(item).expect("too many arguments");
            self.count += 1;
        }
    }

    pub fn push<T>(&mut self, val: T)
    where
        T: 'q + Send + sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    {
        self.args.add(val).expect("too many arguments");
        self.count += 1;
    }

    pub fn len(&self) -> usize {
        self.count
    }
}

impl<'q, DB> IntoArguments<'q, DB> for QueryParams<'q, DB>
where
    DB: Database,
    DB::Arguments<'q>: IntoArguments<'q, DB>,
{
    fn into_arguments(self) -> DB::Arguments<'q> {
        self.args.into_arguments()
    }
}

pub trait QueryPrepare {
    type DB: Database;

    fn placeholder(index: i64) -> String {
        format!("?{}", index)
    }

    fn limit_query<'q>(
        mut query: String,
        args: &mut QueryParams<'q, Self::DB>,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> String
    where
        i64: for<'e> Encode<'e, Self::DB> + Type<Self::DB>,
    {
        if offset.is_some() || limit.is_some() {
            let last_idx = (args.len() + 1) as i64;
            args.push(offset.unwrap_or(0));
            args.push(limit.unwrap_or(-1));
            let limit = replace_arg_placeholders::<Self>(" LIMIT $$, $$", last_idx);
            query.push_str(&limit);
        }
        query
    }

    fn order_by_query(mut query: String, order_by: OrderBy, descending: bool) -> String {
        query.push_str(" ORDER BY ");
        match order_by {
            OrderBy::Id => query.push_str("id"),
        }
        if descending {
            query.push_str(" DESC");
        }
        query
    }
}

pub fn replace_arg_placeholders<Q: QueryPrepare + ?Sized>(
    filter: &str,
    start_index: i64,
) -> String {
    let mut index = start_index;
    let mut buffer: String = String::with_capacity(filter.len());
    let mut remain = filter;
    while let Some(start_offs) = remain.find('$') {
        let mut iter = remain[(start_offs + 1)..].chars();
        if let Some((end_offs, sub_index)) = iter.next().and_then(|c| match c {
            '$' => Some((start_offs + 2, index)),
            '0'..='9' => {
                let mut end_offs = start_offs + 2;
                for c in iter {
                    if c.is_ascii_digit() {
                        end_offs += 1;
                    } else {
                        break;
                    }
                }
                Some((
                    end_offs,
                    remain[(start_offs + 1)..end_offs].parse::<i64>().unwrap() + start_index - 1,
                ))
            }
            _ => None,
        }) {
            buffer.push_str(&remain[..start_offs]);
            buffer.push_str(&Q::placeholder(sub_index));
            remain = &remain[end_offs..];
            index += 1;
        } else {
            buffer.push_str(&remain[..=start_offs]);
            remain = &remain[(start_offs + 1)..];
        }
    }
    buffer.push_str(remain);
    buffer
}

pub(crate) fn decode_tags(tags: Vec<u8>) -> Result<Vec<EncEntryTag>, ()> {
    let mut idx = 0;
    let mut plaintext;
    let mut name_start;
    let mut name_end;
    let mut enc_tags = vec![];
    let end = tags.len();
    loop {
        if idx >= end {
            break;
        }
        plaintext = tags[idx] == b'1';
        // assert ':' at idx + 1
        idx += 2;
        name_start = idx;
        name_end = 0;
        loop {
            if idx >= end || tags[idx] == b',' {
                if name_end == 0 {
                    return Err(());
                }
                let name = hex::decode(&tags[(name_start)..(name_end)]).map_err(|_| ())?;
                let value = hex::decode(&tags[(name_end + 1)..(idx)]).map_err(|_| ())?;
                enc_tags.push(EncEntryTag {
                    name,
                    value,
                    plaintext,
                });
                break;
            }
            if tags[idx] == b':' {
                if name_end != 0 {
                    return Err(());
                }
                name_end = idx;
            }
            idx += 1;
        }
        idx += 1;
    }
    Ok(enc_tags)
}

pub fn decrypt_scan_batch(
    category: Option<String>,
    enc_rows: Vec<EncScanEntry>,
    key: &ProfileKey,
) -> Result<Vec<Entry>, Error> {
    let mut batch = Vec::with_capacity(enc_rows.len());
    for enc_entry in enc_rows {
        batch.push(decrypt_scan_entry(category.as_deref(), enc_entry, key)?);
    }
    Ok(batch)
}

pub fn decrypt_scan_entry(
    category: Option<&str>,
    enc_entry: EncScanEntry,
    key: &ProfileKey,
) -> Result<Entry, Error> {
    let category = match category {
        Some(c) => c.to_owned(),
        None => key.decrypt_entry_category(enc_entry.category)?,
    };
    let name = key.decrypt_entry_name(enc_entry.name)?;
    let value = key.decrypt_entry_value(category.as_bytes(), name.as_bytes(), enc_entry.value)?;
    let tags = key.decrypt_entry_tags(
        decode_tags(enc_entry.tags).map_err(|_| err_msg!(Unexpected, "Error decoding tags"))?,
    )?;
    Ok(Entry::new(enc_entry.kind, category, name, value, tags))
}

pub fn expiry_timestamp(expire_ms: i64) -> Result<Expiry, Error> {
    chrono::Utc::now()
        .checked_add_signed(chrono::Duration::milliseconds(expire_ms))
        .ok_or_else(|| err_msg!(Unexpected, "Invalid expiry timestamp"))
}

#[allow(clippy::type_complexity)]
pub fn encode_tag_filter<Q: QueryPrepare>(
    tag_filter: Option<TagFilter>,
    key: &ProfileKey,
    offset: usize,
) -> Result<Option<(String, Vec<Vec<u8>>)>, Error> {
    if let Some(tag_filter) = tag_filter {
        let tag_query = tag_query(tag_filter.query)?;
        let mut enc = TagSqlEncoder::new(
            |name| key.encrypt_tag_name(ProfileKey::prepare_input(name.as_bytes())),
            |value| key.encrypt_tag_value(ProfileKey::prepare_input(value.as_bytes())),
        );
        if let Some(filter) = enc.encode_query(&tag_query)? {
            let filter = replace_arg_placeholders::<Q>(&filter, (offset as i64) + 1);
            Ok(Some((filter, enc.arguments)))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

// allocate a String while ensuring there is sufficient capacity to reuse during encryption
fn _prepare_string(value: &str) -> String {
    let buf = ProfileKey::prepare_input(value.as_bytes()).into_vec();
    unsafe { String::from_utf8_unchecked(buf) }
}

// convert a slice of tags into a Vec, while ensuring there is
// adequate space in the allocations to reuse them during encryption
pub fn prepare_tags(tags: &[EntryTag]) -> Result<Vec<EntryTag>, Error> {
    let mut result = Vec::with_capacity(tags.len());
    for tag in tags {
        result.push(match tag {
            EntryTag::Plaintext(name, value) => {
                EntryTag::Plaintext(_prepare_string(name), value.clone())
            }
            EntryTag::Encrypted(name, value) => {
                EntryTag::Encrypted(_prepare_string(name), _prepare_string(value))
            }
        });
    }
    Ok(result)
}

pub fn extend_query<'q, Q: QueryPrepare>(
    query: &str,
    args: &mut QueryParams<'q, Q::DB>,
    tag_filter: Option<(String, Vec<Vec<u8>>)>,
    offset: Option<i64>,
    limit: Option<i64>,
    order_by: Option<OrderBy>,
    descending: bool,
) -> Result<String, Error>
where
    i64: for<'e> Encode<'e, Q::DB> + Type<Q::DB>,
    Vec<u8>: for<'e> Encode<'e, Q::DB> + Type<Q::DB>,
{
    let mut query = query.to_string();
    if let Some((filter_clause, filter_args)) = tag_filter {
        args.extend(filter_args);
        query.push_str(" AND "); // assumes WHERE already occurs
        query.push_str(&filter_clause);
    };
    // Only add ordering, and limit/offset, if the query starts with SELECT
    if query.trim_start().to_uppercase().starts_with("SELECT") {
        if let Some(order_by_value) = order_by {
            query = Q::order_by_query(query, order_by_value, descending);
        };

        if offset.is_some() || limit.is_some() {
            query = Q::limit_query(query, args, offset, limit);
        };
    }
    Ok(query)
}

pub fn init_keys(
    method: StoreKeyMethod,
    pass_key: PassKey<'_>,
) -> Result<(ProfileKey, Vec<u8>, StoreKey, String), Error> {
    if method == StoreKeyMethod::RawKey && pass_key.is_empty() {
        // disallow random key for a new database
        return Err(err_msg!(
            Input,
            "Cannot create a store with a blank raw key"
        ));
    }
    let (store_key, store_key_ref) = method.resolve(pass_key)?;
    let profile_key = ProfileKey::new()?;
    let enc_profile_key = encode_profile_key(&profile_key, &store_key)?;
    Ok((
        profile_key,
        enc_profile_key,
        store_key,
        store_key_ref.into_uri(),
    ))
}

pub fn encode_profile_key(
    profile_key: &ProfileKey,
    store_key: &StoreKey,
) -> Result<Vec<u8>, Error> {
    store_key.wrap_data(profile_key.to_bytes()?)
}

#[inline]
pub fn random_profile_name() -> String {
    uuid::Uuid::new_v4().to_string()
}
