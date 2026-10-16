//! Read commands that print live store contents as a table or JSON lines.

use std::io::Write;

use anyhow::{bail, Result};
use askar_storage::inspect::InspectedItem;
use clap::ValueEnum;
use serde_json::{json, Value};

use crate::{
    redact::View,
    source::{Profile, Query, Source},
};

const MAX_CELL: usize = 60;
const PAGE: i64 = 500;

/// How results are printed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Aligned columns for people.
    #[default]
    Table,
    /// One JSON object per line, for scripts.
    Jsonl,
}

/// Options for [`list`].
#[derive(Debug)]
pub struct ListOptions {
    /// Profile name; all profiles when unset.
    pub profile: Option<String>,
    /// Conditions evaluated by the database.
    pub query: Query,
    /// Maximum number of rows in total.
    pub limit: i64,
    /// Continue after this row ID (applies to each profile).
    pub after_id: i64,
    /// How much of the data to show.
    pub view: View,
}

/// Result rows with their column names.
#[derive(Debug)]
pub struct Table {
    /// Column names.
    pub columns: Vec<String>,
    /// One value per column in each row.
    pub rows: Vec<Vec<Value>>,
}

impl Table {
    fn new(columns: &[&str]) -> Self {
        Self {
            columns: columns.iter().map(|column| (*column).to_owned()).collect(),
            rows: Vec::new(),
        }
    }

    /// Print as aligned columns or JSON lines.
    pub fn write(&self, out: &mut dyn Write, format: Format) -> Result<()> {
        match format {
            Format::Jsonl => {
                for row in &self.rows {
                    let object: serde_json::Map<String, Value> = self
                        .columns
                        .iter()
                        .cloned()
                        .zip(row.iter().cloned())
                        .collect();
                    writeln!(out, "{}", Value::Object(object))?;
                }
            }
            Format::Table => {
                let cells: Vec<Vec<String>> = self
                    .rows
                    .iter()
                    .map(|row| row.iter().map(|value| cell(value, MAX_CELL)).collect())
                    .collect();
                let widths: Vec<usize> = self
                    .columns
                    .iter()
                    .enumerate()
                    .map(|(index, column)| {
                        cells
                            .iter()
                            .map(|row| row[index].chars().count())
                            .chain([column.chars().count()])
                            .max()
                            .unwrap_or_default()
                    })
                    .collect();
                let line = |out: &mut dyn Write, row: Vec<&str>| -> Result<()> {
                    let padded: Vec<String> = row
                        .iter()
                        .zip(&widths)
                        .map(|(text, width)| format!("{text:<width$}"))
                        .collect();
                    writeln!(out, "{}", padded.join("  ").trim_end())?;
                    Ok(())
                };
                line(out, self.columns.iter().map(String::as_str).collect())?;
                for row in &cells {
                    line(out, row.iter().map(String::as_str).collect())?;
                }
            }
        }
        Ok(())
    }
}

/// Print arbitrary result rows with the given column names.
pub fn print_rows(
    columns: Vec<String>,
    rows: Vec<Vec<Value>>,
    out: &mut dyn Write,
    format: Format,
) -> Result<()> {
    Table { columns, rows }.write(out, format)
}

fn cell(value: &Value, max: usize) -> String {
    let text = match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        Value::Array(items) => items
            .iter()
            .map(|item| cell(item, usize::MAX))
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    };
    let text = text.replace(['\n', '\r', '\t'], " ");
    if text.chars().count() > max {
        let kept: String = text.chars().take(max.saturating_sub(1)).collect();
        format!("{kept}…")
    } else {
        text
    }
}

pub(crate) fn kind_label(kind: i64) -> &'static str {
    match kind {
        1 => "kms",
        2 => "item",
        _ => "unknown",
    }
}

pub(crate) fn text_or_marker(result: &Result<String, askar_storage::Error>) -> Value {
    match result {
        Ok(text) => json!(text),
        Err(_) => json!("<undecryptable>"),
    }
}

fn describe_value(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(_) => format!("0x{}", hex_string(bytes)),
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn errors(item: &InspectedItem) -> Vec<Value> {
    let mut errors = Vec::new();
    let mut note = |field: &str, error: Option<&askar_storage::Error>| {
        if let Some(error) = error {
            errors.push(json!(format!("{field}: {error}")));
        }
    };
    note("category", item.category.as_ref().err());
    note("name", item.name.as_ref().err());
    note("value", item.value.as_ref().err());
    for tag in &item.tags {
        note("tag", tag.as_ref().err());
    }
    errors
}

/// Tags as `~plaintext` or `encrypted` labels, with `=value` when the view shows values.
fn tag_labels(item: &InspectedItem, view: &View) -> Vec<Value> {
    view.tags(item)
        .into_iter()
        .map(|tag| {
            let label = if tag.plaintext {
                format!("~{}", tag.name)
            } else {
                tag.name
            };
            match tag.value {
                Value::Null => json!(label),
                Value::String(value) => json!(format!("{label}={value}")),
                other => json!(format!("{label}={other}")),
            }
        })
        .collect()
}

/// Value text for display; key-manager values are never shown.
pub(crate) fn value_text(item: &InspectedItem) -> Value {
    if item.kind == 1 {
        return json!("<key material hidden>");
    }
    match &item.value {
        Ok(value) => json!(describe_value(value)),
        Err(_) => json!("<undecryptable>"),
    }
}

pub(crate) fn expiry(item: &InspectedItem) -> Value {
    item.expiry
        .map_or(Value::Null, |expiry| json!(expiry.to_string()))
}

pub(crate) fn value_bytes(item: &InspectedItem) -> Value {
    item.value
        .as_ref()
        .map_or(Value::Null, |value| json!(value.len()))
}

/// The store's profiles and whether their keys unlocked.
pub fn profiles_table(source: &Source) -> Result<Table> {
    let mut table = Table::new(&["id", "profile", "key"]);
    for profile in source.select_profiles(None)? {
        table.rows.push(vec![
            json!(profile.id),
            json!(profile.name),
            json!(profile.key_error().unwrap_or("ok")),
        ]);
    }
    Ok(table)
}

/// Print the store's profiles and whether their keys unlocked.
pub fn profiles(source: &Source, out: &mut dyn Write, format: Format) -> Result<()> {
    profiles_table(source)?.write(out, format)
}

/// Row counts and encrypted value sizes per category.
pub async fn stats_table(source: &mut Source, profile: Option<&str>) -> Result<Table> {
    if let Some(name) = profile {
        source.select_profiles(Some(name))?;
    }
    let mut table = Table::new(&["profile", "kind", "category", "items", "expired", "bytes"]);
    for stat in source.stats().await? {
        if profile.is_some_and(|name| name != stat.profile) {
            continue;
        }
        table.rows.push(vec![
            json!(stat.profile),
            json!(kind_label(stat.kind)),
            json!(stat.category),
            json!(stat.items),
            json!(stat.expired),
            json!(stat.encrypted_value_bytes),
        ]);
    }
    Ok(table)
}

/// Print row counts and encrypted value sizes per category.
pub async fn stats(
    source: &mut Source,
    profile: Option<&str>,
    out: &mut dyn Write,
    format: Format,
) -> Result<()> {
    stats_table(source, profile).await?.write(out, format)
}

/// Matching entries, up to the limit.
pub async fn list_table(source: &mut Source, options: &ListOptions) -> Result<Table> {
    if options.limit <= 0 {
        bail!("The limit must be positive");
    }
    if options.query.name.is_some() {
        options.view.check_name_filter()?;
    }
    for tag in &options.query.tags {
        options.view.check_tag_filter(&tag.name)?;
    }
    let mut columns = vec![
        "profile",
        "id",
        "kind",
        "category",
        "name",
        "value_bytes",
        "expiry",
        "tags",
        "errors",
    ];
    if !matches!(options.view, View::Hidden) {
        columns.push("value");
    }
    let mut table = Table::new(&columns);
    let mut remaining = options.limit;
    for profile in source.select_profiles(options.profile.as_deref())? {
        let mut after_id = options.after_id;
        while remaining > 0 {
            let page = source
                .scan(&profile, &options.query, after_id, remaining.min(PAGE))
                .await?;
            let Some(last) = page.last() else { break };
            after_id = last.id;
            remaining -= page.len() as i64;
            for item in &page {
                let mut row = vec![
                    json!(profile.name),
                    json!(item.id),
                    json!(kind_label(item.kind)),
                    text_or_marker(&item.category),
                    options.view.name(item),
                    value_bytes(item),
                    expiry(item),
                    Value::Array(tag_labels(item, &options.view)),
                    Value::Array(errors(item)),
                ];
                if !matches!(options.view, View::Hidden) {
                    row.push(options.view.value(item));
                }
                table.rows.push(row);
            }
        }
    }
    Ok(table)
}

/// Print matching entries, up to the limit.
pub async fn list(
    source: &mut Source,
    options: &ListOptions,
    out: &mut dyn Write,
    format: Format,
) -> Result<()> {
    list_table(source, options).await?.write(out, format)
}

fn pretty(text: &str) -> String {
    serde_json::from_str::<Value>(text)
        .and_then(|value| serde_json::to_string_pretty(&value))
        .unwrap_or_else(|_| text.to_owned())
}

/// One entry as a JSON object, as far as the view allows.
pub async fn get_entry(
    source: &mut Source,
    profile: &Profile,
    id: i64,
    view: &View,
) -> Result<Value> {
    let Some(item) = source.fetch(profile, id).await? else {
        bail!("No entry with id {id} in profile {}", profile.name);
    };
    let value = match (view, item.kind) {
        (_, 1) => json!("<key material hidden>"),
        (View::Hidden, _) => json!(format!(
            "<{} bytes; use --reveal to show>",
            item.value.as_ref().map_or(0, |value| value.len())
        )),
        _ => view.value(&item),
    };
    Ok(json!({
        "profile": profile.name,
        "id": item.id,
        "kind": kind_label(item.kind),
        "category": text_or_marker(&item.category),
        "name": view.name(&item),
        "expiry": expiry(&item),
        "tags": tag_labels(&item, view),
        "errors": errors(&item),
        "value": value,
    }))
}

/// Print one entry in full, as far as the view allows.
pub async fn get(
    source: &mut Source,
    profile: &Profile,
    id: i64,
    view: &View,
    out: &mut dyn Write,
    format: Format,
) -> Result<()> {
    let entry = get_entry(source, profile, id, view).await?;
    match format {
        Format::Jsonl => writeln!(out, "{entry}")?,
        Format::Table => {
            let field = |name: &str| cell(&entry[name], usize::MAX);
            writeln!(out, "profile:  {}", field("profile"))?;
            writeln!(out, "id:       {}", field("id"))?;
            writeln!(out, "kind:     {}", field("kind"))?;
            writeln!(out, "category: {}", field("category"))?;
            writeln!(out, "name:     {}", field("name"))?;
            writeln!(out, "expiry:   {}", field("expiry"))?;
            writeln!(out, "tags:     {}", field("tags"))?;
            for error in entry["errors"].as_array().into_iter().flatten() {
                writeln!(out, "error:    {}", cell(error, usize::MAX))?;
            }
            let shown = match &entry["value"] {
                Value::String(text) => pretty(text),
                other => serde_json::to_string_pretty(other)?,
            };
            writeln!(out, "value:\n{shown}")?;
        }
    }
    Ok(())
}
