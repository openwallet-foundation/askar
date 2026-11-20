//! Read-only SQL over a live store: a virtual table decrypts rows as SQLite asks for them.
//!
//! The `items` table pushes equality conditions on `profile`, `id`, `kind`, `category`,
//! `name` and the hidden `ptag`/`etag` columns down to the database, so they stay fast on
//! large stores. Any other condition is evaluated by SQLite after decryption.

use std::{collections::VecDeque, marker::PhantomData, os::raw::c_int, sync::Arc};

use anyhow::{bail, Result};
use askar_storage::inspect::{ExpiryFilter, InspectedItem};
use rusqlite::{
    ffi,
    hooks::{AuthAction, AuthContext, Authorization},
    types::ValueRef,
    vtab::{
        eponymous_only_module, Context as VtabContext, CreateVTab, IndexConstraintOp, IndexInfo,
        VTab, VTabConnection, VTabCursor, VTabKind, Values,
    },
    Connection,
};
use serde_json::{json, Map, Value};
use tokio::{runtime::Handle, sync::Mutex};

use crate::{
    commands::{errors, kind_label, text_or_marker},
    redact::View,
    source::{Profile, Query, Source, TagCondition},
};

const PAGE: i64 = 200;

const COL_PROFILE: c_int = 0;
const COL_ID: c_int = 1;
const COL_KIND: c_int = 2;
const COL_CATEGORY: c_int = 3;
const COL_NAME: c_int = 4;
const COL_VALUE: c_int = 5;
const COL_VALUE_BYTES: c_int = 6;
const COL_EXPIRY: c_int = 7;
const COL_PTAGS: c_int = 8;
const COL_ETAGS: c_int = 9;
const COL_ERRORS: c_int = 10;
const COL_PTAG: c_int = 11;
const COL_ETAG: c_int = 12;
const COL_MODE: c_int = 13;

const SCHEMA: &str = "CREATE TABLE x(profile TEXT, id INTEGER, kind TEXT, category TEXT, \
    name TEXT, value TEXT, value_bytes INTEGER, expiry TEXT, ptags TEXT, etags TEXT, \
    errors TEXT, ptag HIDDEN, etag HIDDEN, expiry_mode HIDDEN)";

struct Shared {
    source: Arc<Mutex<Source>>,
    handle: Handle,
    view: View,
}

fn module_error(error: impl std::fmt::Display) -> rusqlite::Error {
    rusqlite::Error::ModuleError(format!("{error:#}"))
}

#[repr(C)]
struct ItemsTable {
    base: ffi::sqlite3_vtab,
    shared: Arc<Shared>,
}

unsafe impl<'vtab> VTab<'vtab> for ItemsTable {
    type Aux = Arc<Shared>;
    type Cursor = ItemsCursor<'vtab>;

    fn connect(
        _db: &mut VTabConnection,
        aux: Option<&Self::Aux>,
        _args: &[&[u8]],
    ) -> rusqlite::Result<(String, Self)> {
        let shared = aux
            .cloned()
            .ok_or_else(|| module_error("missing store connection"))?;
        Ok((
            SCHEMA.to_owned(),
            Self {
                base: ffi::sqlite3_vtab::default(),
                shared,
            },
        ))
    }

    fn best_index(&self, info: &mut IndexInfo) -> rusqlite::Result<()> {
        let mut pushed = Vec::new();
        for (index, constraint) in info.constraints().enumerate() {
            if constraint.is_usable()
                && constraint.operator() == IndexConstraintOp::SQLITE_INDEX_CONSTRAINT_EQ
                && matches!(
                    constraint.column(),
                    COL_PROFILE
                        | COL_ID
                        | COL_KIND
                        | COL_CATEGORY
                        | COL_NAME
                        | COL_PTAG
                        | COL_ETAG
                        | COL_MODE
                )
            {
                pushed.push((index, constraint.column()));
            }
        }
        let mut columns = Vec::new();
        for (position, (index, column)) in pushed.iter().enumerate() {
            let mut usage = info.constraint_usage(*index);
            usage.set_argv_index(position as c_int + 1);
            // The database applies the condition exactly, so SQLite need not re-check it.
            usage.set_omit(true);
            columns.push(column.to_string());
        }
        info.set_idx_str(&columns.join(","));
        let selective = pushed
            .iter()
            .filter(|(_, column)| *column != COL_MODE)
            .count();
        info.set_estimated_cost(1e9 / 10f64.powi(selective as i32));
        info.set_estimated_rows(1_000_000 / 10i64.pow(selective as u32));
        Ok(())
    }

    fn open(&'vtab mut self) -> rusqlite::Result<ItemsCursor<'vtab>> {
        Ok(ItemsCursor {
            base: ffi::sqlite3_vtab_cursor::default(),
            shared: Arc::clone(&self.shared),
            query: Query::default(),
            profiles: VecDeque::new(),
            current: None,
            after_id: 0,
            page: VecDeque::new(),
            row: None,
            row_profile: String::new(),
            rowid: 0,
            phantom: PhantomData,
        })
    }
}

impl<'vtab> CreateVTab<'vtab> for ItemsTable {
    const KIND: VTabKind = VTabKind::EponymousOnly;
}

#[repr(C)]
struct ItemsCursor<'vtab> {
    base: ffi::sqlite3_vtab_cursor,
    shared: Arc<Shared>,
    query: Query,
    profiles: VecDeque<Profile>,
    current: Option<Profile>,
    after_id: i64,
    page: VecDeque<InspectedItem>,
    row: Option<InspectedItem>,
    row_profile: String,
    rowid: i64,
    phantom: PhantomData<&'vtab ItemsTable>,
}

fn text_arg(value: ValueRef<'_>, column: &str) -> rusqlite::Result<String> {
    match value {
        ValueRef::Text(bytes) => String::from_utf8(bytes.to_vec()).map_err(module_error),
        _ => Err(module_error(format!("{column} must be compared to text"))),
    }
}

impl ItemsCursor<'_> {
    fn apply(&mut self, column: c_int, value: ValueRef<'_>) -> rusqlite::Result<Option<String>> {
        let mut profile = None;
        match column {
            COL_PROFILE => profile = Some(text_arg(value, "profile")?),
            COL_ID => match value {
                ValueRef::Integer(id) => self.query.id = Some(id),
                _ => return Err(module_error("id must be compared to an integer")),
            },
            COL_KIND => {
                self.query.kind = Some(match value {
                    ValueRef::Integer(kind @ (1 | 2)) => kind,
                    ValueRef::Text(b"kms") => 1,
                    ValueRef::Text(b"item") => 2,
                    _ => return Err(module_error("kind must be 'item' or 'kms'")),
                })
            }
            COL_CATEGORY => self.query.category = Some(text_arg(value, "category")?),
            COL_NAME => {
                self.shared.view.check_name_filter().map_err(module_error)?;
                self.query.name = Some(text_arg(value, "name")?)
            }
            COL_PTAG | COL_ETAG => {
                let spec = text_arg(value, "ptag/etag")?;
                let tag = TagCondition::parse(&spec, column == COL_PTAG).map_err(module_error)?;
                self.shared
                    .view
                    .check_tag_filter(&tag.name)
                    .map_err(module_error)?;
                self.query.tags.push(tag);
            }
            COL_MODE => {
                self.query.expiry = match text_arg(value, "expiry_mode")?.as_str() {
                    "any" => ExpiryFilter::Any,
                    "live" => ExpiryFilter::LiveOnly,
                    "expired" => ExpiryFilter::ExpiredOnly,
                    _ => return Err(module_error("expiry_mode must be any, live or expired")),
                }
            }
            _ => {}
        }
        Ok(profile)
    }

    fn advance(&mut self) -> rusqlite::Result<()> {
        loop {
            if let Some(item) = self.page.pop_front() {
                self.after_id = item.id;
                self.row_profile = self
                    .current
                    .as_ref()
                    .map(|p| p.name.clone())
                    .unwrap_or_default();
                self.row = Some(item);
                self.rowid += 1;
                return Ok(());
            }
            match self.current.clone() {
                None => match self.profiles.pop_front() {
                    Some(profile) => {
                        self.current = Some(profile);
                        self.after_id = 0;
                    }
                    None => {
                        self.row = None;
                        return Ok(());
                    }
                },
                Some(profile) => {
                    let shared = Arc::clone(&self.shared);
                    let (query, after_id) = (self.query.clone(), self.after_id);
                    let page = shared
                        .handle
                        .block_on(async {
                            shared
                                .source
                                .lock()
                                .await
                                .scan(&profile, &query, after_id, PAGE)
                                .await
                        })
                        .map_err(module_error)?;
                    if page.is_empty() {
                        self.current = None;
                    } else {
                        self.page = page.into();
                    }
                }
            }
        }
    }
}

unsafe impl VTabCursor for ItemsCursor<'_> {
    fn filter(
        &mut self,
        _idx_num: c_int,
        idx_str: Option<&str>,
        args: &Values<'_>,
    ) -> rusqlite::Result<()> {
        self.query = Query::default();
        self.page.clear();
        self.current = None;
        self.row = None;
        self.after_id = 0;
        self.rowid = 0;
        let mut profile = None;
        let mut impossible = false;
        let columns = idx_str
            .unwrap_or_default()
            .split(',')
            .filter(|c| !c.is_empty());
        for (value, column) in args.iter().zip(columns) {
            if value == ValueRef::Null {
                impossible = true;
                continue;
            }
            let column: c_int = column.parse().map_err(module_error)?;
            if let Some(name) = self.apply(column, value)? {
                profile = Some(name);
            }
        }
        self.profiles = if impossible {
            VecDeque::new()
        } else {
            // An unknown profile name matches nothing, as with any other equality filter.
            let shared = Arc::clone(&self.shared);
            let source = shared.handle.block_on(shared.source.lock());
            source
                .select_profiles(profile.as_deref())
                .unwrap_or_default()
                .into()
        };
        self.advance()
    }

    fn next(&mut self) -> rusqlite::Result<()> {
        self.advance()
    }

    fn eof(&self) -> bool {
        self.row.is_none()
    }

    fn column(&self, ctx: &mut VtabContext, column: c_int) -> rusqlite::Result<()> {
        let Some(item) = self.row.as_ref() else {
            return ctx.set_result(&None::<String>);
        };
        let view = &self.shared.view;
        match column {
            COL_PROFILE => ctx.set_result(&self.row_profile),
            COL_ID => ctx.set_result(&item.id),
            COL_KIND => ctx.set_result(&kind_label(item.kind)),
            COL_CATEGORY => {
                ctx.set_result(&text_or_marker(&item.category).as_str().map(str::to_owned))
            }
            COL_NAME => ctx.set_result(&view.name(item).as_str().map(str::to_owned)),
            COL_VALUE => ctx.set_result(&view.value_as_text(item)),
            COL_VALUE_BYTES => ctx.set_result(&item.value.as_ref().ok().map(|v| v.len() as i64)),
            COL_EXPIRY => ctx.set_result(&item.expiry.map(|expiry| expiry.to_string())),
            COL_PTAGS => ctx.set_result(&tag_object(item, true, view)),
            COL_ETAGS => ctx.set_result(&tag_object(item, false, view)),
            COL_ERRORS => {
                let errors = errors(item);
                ctx.set_result(&(!errors.is_empty()).then(|| Value::Array(errors).to_string()))
            }
            _ => ctx.set_result(&None::<String>),
        }
    }

    fn rowid(&self) -> rusqlite::Result<i64> {
        Ok(self.rowid)
    }
}

fn tag_object(item: &InspectedItem, plaintext: bool, view: &View) -> String {
    let mut object = Map::new();
    for tag in view.tags(item) {
        if tag.plaintext == plaintext {
            object.insert(tag.name, tag.value);
        }
    }
    Value::Object(object).to_string()
}

fn to_json(value: ValueRef<'_>) -> Value {
    match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(number) => json!(number),
        ValueRef::Real(number) => json!(number),
        ValueRef::Text(bytes) => json!(String::from_utf8_lossy(bytes)),
        ValueRef::Blob(bytes) => {
            let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            json!(format!("0x{hex}"))
        }
    }
}

/// Result of a query: column names, rows, and whether the row limit cut it short.
#[derive(Debug)]
pub struct Rows {
    /// Column names.
    pub columns: Vec<String>,
    /// Result rows.
    pub rows: Vec<Vec<Value>>,
    /// Whether more rows were available than the limit allowed.
    pub truncated: bool,
}

/// Run a read-only SQL statement against the `items` table.
///
/// What the view withholds is NULL; key-manager values always are.
pub async fn query(
    source: Arc<Mutex<Source>>,
    sql: String,
    view: View,
    limit: usize,
) -> Result<Rows> {
    let shared = Arc::new(Shared {
        source,
        handle: Handle::current(),
        view,
    });
    tokio::task::spawn_blocking(move || execute(shared, &sql, limit)).await?
}

fn execute(shared: Arc<Shared>, sql: &str, limit: usize) -> Result<Rows> {
    let connection = Connection::open_in_memory()?;
    connection.create_module("items", eponymous_only_module::<ItemsTable>(), Some(shared))?;
    connection.authorizer(Some(|context: AuthContext<'_>| match context.action {
        AuthAction::Select
        | AuthAction::Read { .. }
        | AuthAction::Function { .. }
        | AuthAction::Recursive => Authorization::Allow,
        _ => Authorization::Deny,
    }));
    let mut statement = match connection.prepare(sql) {
        Ok(statement) => statement,
        Err(rusqlite::Error::MultipleStatement) => bail!("Run one statement at a time"),
        Err(error) => bail!("{error}"),
    };
    // SQLite silently ignores text after the first statement; refuse it instead.
    let trim = |text: &str| text.trim().trim_end_matches(';').trim_end().to_owned();
    if trim(&statement.expanded_sql().unwrap_or_default()) != trim(sql) {
        bail!("Run one statement at a time");
    }
    let columns: Vec<String> = statement
        .column_names()
        .into_iter()
        .map(str::to_owned)
        .collect();
    let width = columns.len();
    let mut rows = statement.query([])?;
    let mut collected = Vec::new();
    let mut truncated = false;
    while let Some(row) = rows.next()? {
        if collected.len() >= limit {
            truncated = true;
            break;
        }
        collected.push(
            (0..width)
                .map(|index| row.get_ref(index).map(to_json))
                .collect::<rusqlite::Result<Vec<_>>>()?,
        );
    }
    Ok(Rows {
        columns,
        rows: collected,
        truncated,
    })
}
