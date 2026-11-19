//! Aggregate structure of one category, for planning queries without reading data.
//!
//! Values are decrypted in memory but only counts, types and lengths leave this module.
//! Real values appear only for JSON paths and tags that the policy lists.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    hash::{DefaultHasher, Hash, Hasher},
};

use anyhow::Result;
use askar_storage::{entry::EntryTag, inspect::InspectedItem};
use serde_json::{json, Value};

use crate::{
    redact::{Policy, MAX_DEPTH, MAX_KEYS},
    source::{Query, Source},
};

const PAGE: i64 = 500;
const MAX_DISTINCT: usize = 10_000;
const MAX_TRACKED: usize = 50;
const TOP: usize = 10;
const ARRAY_SAMPLE: usize = 100;

/// Options for [`describe`].
#[derive(Debug)]
pub struct DescribeOptions {
    /// Profile name; all profiles when unset.
    pub profile: Option<String>,
    /// How many entries to inspect, taken in id order.
    pub sample: usize,
}

/// A table of facts about a category.
#[derive(Debug)]
pub struct Description {
    /// Column names.
    pub columns: Vec<String>,
    /// Rows, each with one value per column.
    pub rows: Vec<Vec<Value>>,
}

#[derive(Default)]
struct Field {
    types: BTreeSet<&'static str>,
    count: u64,
    docs: u64,
    distinct: HashSet<u64>,
    overflow: bool,
    lengths: Option<(usize, usize)>,
    top: HashMap<String, u64>,
}

impl Field {
    fn note_length(&mut self, length: usize) {
        self.lengths = Some(match self.lengths {
            Some((min, max)) => (min.min(length), max.max(length)),
            None => (length, length),
        });
    }

    fn note_value(&mut self, text: &str, keep: bool) {
        let mut hasher = DefaultHasher::new();
        text.hash(&mut hasher);
        let hash = hasher.finish();
        if self.distinct.len() < MAX_DISTINCT {
            self.distinct.insert(hash);
        } else if !self.distinct.contains(&hash) {
            self.overflow = true;
        }
        if keep && (self.top.contains_key(text) || self.top.len() < MAX_TRACKED) {
            *self.top.entry(text.to_owned()).or_default() += 1;
        }
    }

    fn distinct_count(&self) -> Value {
        if self.overflow {
            json!(format!(">{MAX_DISTINCT}"))
        } else {
            json!(self.distinct.len())
        }
    }

    fn top_values(&self) -> Value {
        let mut top: Vec<(&String, &u64)> = self.top.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        Value::Array(
            top.into_iter()
                .take(TOP)
                .map(|(value, count)| json!(format!("{value} ({count})")))
                .collect(),
        )
    }
}

struct Collector<'a> {
    policy: &'a Policy,
    category: &'a str,
    fields: BTreeMap<String, Field>,
    tags: BTreeMap<(bool, String), Field>,
    sampled: u64,
    undecryptable: u64,
    json_documents: u64,
    text: u64,
    binary: u64,
    with_expiry: u64,
    sizes: Vec<usize>,
}

impl<'a> Collector<'a> {
    fn new(policy: &'a Policy, category: &'a str) -> Self {
        Self {
            policy,
            category,
            fields: BTreeMap::new(),
            tags: BTreeMap::new(),
            sampled: 0,
            undecryptable: 0,
            json_documents: 0,
            text: 0,
            binary: 0,
            with_expiry: 0,
            sizes: Vec::new(),
        }
    }

    fn add(&mut self, item: &InspectedItem) {
        self.sampled += 1;
        if item.expiry.is_some() {
            self.with_expiry += 1;
        }
        match &item.value {
            Err(_) => self.undecryptable += 1,
            Ok(bytes) => {
                self.sizes.push(bytes.len());
                match std::str::from_utf8(bytes) {
                    Err(_) => self.binary += 1,
                    Ok(text) => match serde_json::from_str::<Value>(text) {
                        Err(_) => self.text += 1,
                        Ok(document) => {
                            self.json_documents += 1;
                            self.walk(&document, "", 0, &mut HashSet::new());
                        }
                    },
                }
            }
        }
        for tag in item.tags.iter().filter_map(|tag| tag.as_ref().ok()) {
            let (name, value, plaintext) = match tag {
                EntryTag::Plaintext(name, value) => (name, value, true),
                EntryTag::Encrypted(name, value) => (name, value, false),
            };
            let keep = self.policy.shows_tag(name);
            let field = self.tags.entry((plaintext, name.clone())).or_default();
            field
                .types
                .insert(if plaintext { "plaintext" } else { "encrypted" });
            field.count += 1;
            field.docs += 1;
            field.note_value(value, keep);
        }
    }

    fn walk(&mut self, value: &Value, path: &str, depth: usize, seen: &mut HashSet<String>) {
        let first_in_document = seen.insert(path.to_owned());
        let keep = self.policy.shows_path(self.category, path);
        let field = self.fields.entry(path.to_owned()).or_default();
        field.count += 1;
        if first_in_document {
            field.docs += 1;
        }
        match value {
            Value::Object(map) => {
                field.types.insert("object");
                if depth >= MAX_DEPTH {
                    return;
                }
                for (key, child) in map.iter().take(MAX_KEYS) {
                    let segment = if self.policy.is_structure_key(key) {
                        key.as_str()
                    } else {
                        "*"
                    };
                    let child_path = if path.is_empty() {
                        segment.to_owned()
                    } else {
                        format!("{path}.{segment}")
                    };
                    self.walk(child, &child_path, depth + 1, seen);
                }
            }
            Value::Array(items) => {
                field.types.insert("array");
                field.note_length(items.len());
                if depth >= MAX_DEPTH {
                    return;
                }
                let child_path = format!("{path}[]");
                for item in items.iter().take(ARRAY_SAMPLE) {
                    self.walk(item, &child_path, depth + 1, seen);
                }
            }
            Value::String(text) => {
                field.types.insert("string");
                field.note_length(text.chars().count());
                field.note_value(text, keep);
            }
            Value::Number(number) => {
                field.types.insert("number");
                field.note_value(&number.to_string(), keep);
            }
            Value::Bool(flag) => {
                field.types.insert("bool");
                field.note_value(&flag.to_string(), true);
            }
            Value::Null => {
                field.types.insert("null");
            }
        }
    }
}

fn percent(part: u64, whole: u64) -> Value {
    if whole == 0 {
        return Value::Null;
    }
    json!((part as f64 * 1000.0 / whole as f64).round() / 10.0)
}

fn row(section: &str, name: Value, cells: [Value; 6]) -> Vec<Value> {
    let mut row = vec![json!(section), name];
    row.extend(cells);
    row
}

/// Summarize the structure of the entries in one category.
pub async fn describe(
    source: &mut Source,
    category: &str,
    options: &DescribeOptions,
    policy: &Policy,
) -> Result<Description> {
    let profiles = source.select_profiles(options.profile.as_deref())?;
    let (mut total, mut expired) = (0, 0);
    for stat in source.stats().await? {
        let in_scope = match options.profile.as_deref() {
            Some(name) => name == stat.profile,
            None => true,
        };
        if stat.category == category && stat.kind == 2 && in_scope {
            total += stat.items;
            expired += stat.expired;
        }
    }

    let mut collector = Collector::new(policy, category);
    let query = Query {
        category: Some(category.to_owned()),
        kind: Some(2),
        ..Default::default()
    };
    for profile in &profiles {
        let mut after_id = 0;
        while (collector.sampled as usize) < options.sample {
            let wanted = (options.sample - collector.sampled as usize).min(PAGE as usize);
            let page = source
                .scan(profile, &query, after_id, wanted as i64)
                .await?;
            let Some(last) = page.last() else { break };
            after_id = last.id;
            for item in &page {
                collector.add(item);
            }
        }
    }

    let none = || Value::Null;
    let mut rows = Vec::new();
    let mut summary = |name: &str, count: Value| {
        rows.push(row(
            "summary",
            json!(name),
            [none(), count, none(), none(), none(), none()],
        ));
    };
    summary("entries", json!(total));
    summary("expired", json!(expired));
    summary("sampled", json!(collector.sampled));
    summary("json_documents", json!(collector.json_documents));
    summary("text_values", json!(collector.text));
    summary("binary_values", json!(collector.binary));
    summary("undecryptable", json!(collector.undecryptable));
    summary("with_expiry", json!(collector.with_expiry));
    collector.sizes.sort_unstable();
    if let (Some(min), Some(max)) = (collector.sizes.first(), collector.sizes.last()) {
        summary("value_bytes_min", json!(min));
        summary(
            "value_bytes_median",
            json!(collector.sizes[collector.sizes.len() / 2]),
        );
        summary("value_bytes_max", json!(max));
    }

    for (path, field) in &collector.fields {
        let name = if path.is_empty() { "$" } else { path.as_str() };
        rows.push(row(
            "field",
            json!(name),
            [
                json!(field.types.iter().copied().collect::<Vec<_>>().join("|")),
                json!(field.count),
                percent(field.docs, collector.json_documents),
                field.distinct_count(),
                field
                    .lengths
                    .map_or(Value::Null, |(min, max)| json!(format!("{min}-{max}"))),
                field.top_values(),
            ],
        ));
    }
    for ((plaintext, name), field) in &collector.tags {
        let label = if *plaintext {
            format!("~{name}")
        } else {
            name.clone()
        };
        rows.push(row(
            "tag",
            json!(label),
            [
                json!(field.types.iter().copied().collect::<Vec<_>>().join("|")),
                json!(field.count),
                percent(field.docs, collector.sampled),
                field.distinct_count(),
                Value::Null,
                field.top_values(),
            ],
        ));
    }

    Ok(Description {
        columns: [
            "section",
            "name",
            "types",
            "count",
            "present_pct",
            "distinct",
            "length",
            "values",
        ]
        .map(String::from)
        .to_vec(),
        rows,
    })
}
