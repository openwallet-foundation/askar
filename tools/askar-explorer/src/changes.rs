//! Change sets: edits that an agent proposes and a person reviews and applies.
//!
//! A proposal describes edits (set a JSON field, change a tag, remove or add an entry) and
//! never contains old values. The explorer resolves each edit against the real entry, records
//! a fingerprint of what the proposal was based on, and applies it only if the entry is
//! unchanged. Proposal creation is deliberately uninformative about data: it does not say
//! whether a guessed value or name already exists or whether an edit changes anything, so it
//! cannot be used to test guesses. A person sees all of that when reviewing.

use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use askar_storage::{entry::EntryTag, inspect::InspectedItem, ManageBackend};
use chrono::{NaiveDateTime, Utc};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use similar::TextDiff;

use crate::{
    apply::{self, Change, Record, Tag},
    read_pass_key,
    source::{Profile, Query, Source},
};

const MAX_OPS: usize = 100;
const MAX_PENDING: usize = 50;
const MAX_TITLE: usize = 200;
const MAX_RATIONALE: usize = 4000;
const MAX_VALUE_BYTES: usize = 256 * 1024;
const TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S%.f";

/// A tag to set on an inserted entry.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TagSpec {
    /// Tag name.
    pub name: String,
    /// Tag value.
    pub value: String,
    /// Store the value in plaintext so that it can be compared and ordered.
    #[serde(default)]
    pub plaintext: bool,
}

/// One edit. Entries are addressed by profile name and database id, as shown by `ls`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Op {
    /// Remove an entry.
    Remove {
        /// Profile name.
        profile: String,
        /// Entry id.
        id: i64,
    },
    /// Replace the value at a JSON Pointer (RFC 6901) inside a JSON value, or add a key to an
    /// existing object. An empty pointer replaces the whole value.
    SetJson {
        /// Profile name.
        profile: String,
        /// Entry id.
        id: i64,
        /// JSON Pointer such as `/state` or `/items/0/status`.
        pointer: String,
        /// The new JSON value.
        value: Value,
    },
    /// Add or replace a tag.
    SetTag {
        /// Profile name.
        profile: String,
        /// Entry id.
        id: i64,
        /// Tag name.
        name: String,
        /// Tag value.
        value: String,
        /// Whether the tag is a plaintext tag.
        #[serde(default)]
        plaintext: bool,
    },
    /// Remove a tag.
    RemoveTag {
        /// Profile name.
        profile: String,
        /// Entry id.
        id: i64,
        /// Tag name.
        name: String,
        /// Whether the tag is a plaintext tag.
        #[serde(default)]
        plaintext: bool,
    },
    /// Set the expiry (UTC, `YYYY-MM-DD HH:MM:SS`) or clear it with null.
    SetExpiry {
        /// Profile name.
        profile: String,
        /// Entry id.
        id: i64,
        /// New expiry, or null for none.
        expiry: Option<String>,
    },
    /// Add a new entry whose value is JSON.
    Insert {
        /// Profile name.
        profile: String,
        /// Category.
        category: String,
        /// Entry name.
        name: String,
        /// The JSON value.
        value: Value,
        /// Tags.
        #[serde(default)]
        tags: Vec<TagSpec>,
        /// Expiry (UTC, `YYYY-MM-DD HH:MM:SS`).
        #[serde(default)]
        expiry: Option<String>,
    },
}

impl Op {
    fn target(&self) -> Option<(&str, i64)> {
        match self {
            Self::Remove { profile, id }
            | Self::SetJson { profile, id, .. }
            | Self::SetTag { profile, id, .. }
            | Self::RemoveTag { profile, id, .. }
            | Self::SetExpiry { profile, id, .. } => Some((profile, *id)),
            Self::Insert { .. } => None,
        }
    }
}

/// What an agent submits.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalRequest {
    /// A short summary for the reviewer.
    pub title: String,
    /// Why the change is wanted.
    #[serde(default)]
    pub rationale: String,
    /// The edits, applied in order.
    pub ops: Vec<Op>,
}

/// Where a proposal stands.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Waiting for a person.
    Pending,
    /// A person applied it.
    Applied,
    /// A person turned it down.
    Rejected,
}

/// The state of an entry when the proposal was made.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Expected {
    /// Profile name.
    pub profile: String,
    /// Entry id.
    pub id: i64,
    /// Fingerprint of the entry's category, name, value, tags and expiry.
    pub fingerprint: String,
}

/// A stored proposal.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Proposal {
    /// Identifier such as `p-3fa9c1d07b2e`.
    pub id: String,
    /// When it was made (UTC).
    pub created_at: String,
    /// Summary.
    pub title: String,
    /// Reasoning.
    pub rationale: String,
    /// Current status.
    pub status: Status,
    /// The edits.
    pub ops: Vec<Op>,
    /// Fingerprints of the entries the edits were checked against.
    pub expected: Vec<Expected>,
}

/// A directory of proposals, one file each.
#[derive(Clone, Debug)]
pub struct ProposalStore {
    dir: PathBuf,
}

fn valid_id(id: &str) -> bool {
    id.len() == 14
        && id.starts_with("p-")
        && id[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl ProposalStore {
    /// Use `dir`, which is created when the first proposal is saved.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, id: &str) -> Result<PathBuf> {
        ensure!(valid_id(id), "Not a proposal id: {id:?}");
        Ok(self.dir.join(format!("{id}.json")))
    }

    fn write(&self, path: &Path, proposal: &Proposal, create_new: bool) -> Result<()> {
        let mut open = OpenOptions::new();
        open.write(true);
        if create_new {
            open.create_new(true);
        } else {
            open.truncate(true);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(0o600);
        }
        let mut file = open
            .open(path)
            .with_context(|| format!("Cannot write {}", path.display()))?;
        file.write_all(serde_json::to_string_pretty(proposal)?.as_bytes())?;
        file.write_all(b"\n")?;
        Ok(())
    }

    /// Save a new proposal, refusing when too many are waiting.
    pub fn create(&self, proposal: &Proposal) -> Result<()> {
        let pending = self
            .list()?
            .iter()
            .filter(|existing| existing.status == Status::Pending)
            .count();
        ensure!(
            pending < MAX_PENDING,
            "There are already {MAX_PENDING} proposals waiting for review"
        );
        fs::create_dir_all(&self.dir)?;
        self.write(&self.path(&proposal.id)?, proposal, true)
    }

    /// Read one proposal.
    pub fn load(&self, id: &str) -> Result<Proposal> {
        let path = self.path(id)?;
        let text = fs::read_to_string(&path).with_context(|| format!("No proposal {id}"))?;
        serde_json::from_str(&text)
            .with_context(|| format!("{} is not a valid proposal", path.display()))
    }

    /// All proposals, oldest first.
    pub fn list(&self) -> Result<Vec<Proposal>> {
        let mut proposals = Vec::new();
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(proposals),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let path = entry?.path();
            let Some(id) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            if path.extension().is_some_and(|ext| ext == "json") && valid_id(id) {
                proposals.push(self.load(id)?);
            }
        }
        proposals.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        Ok(proposals)
    }

    /// Move a pending proposal to a final status.
    pub fn finish(&self, id: &str, status: Status) -> Result<()> {
        let mut proposal = self.load(id)?;
        ensure!(
            proposal.status == Status::Pending,
            "Proposal {id} is already {:?}",
            proposal.status
        );
        proposal.status = status;
        self.write(&self.path(id)?, &proposal, false)
    }

    /// Append a line recording a decision; it holds no values.
    pub fn log(&self, line: &str) -> Result<()> {
        fs::create_dir_all(&self.dir)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("changes.log"))?;
        writeln!(file, "{} {line}", Utc::now().format("%Y-%m-%dT%H:%M:%SZ"))?;
        Ok(())
    }
}

/// Fingerprint the parts of an entry that an edit could depend on.
pub fn fingerprint(item: &InspectedItem) -> Result<String> {
    let category = item
        .category
        .as_ref()
        .map_err(|e| anyhow!("category: {e}"))?;
    let name = item.name.as_ref().map_err(|e| anyhow!("name: {e}"))?;
    let value = item.value.as_ref().map_err(|e| anyhow!("value: {e}"))?;
    let mut tags: Vec<(bool, &str, &str)> = Vec::new();
    for tag in &item.tags {
        match tag.as_ref().map_err(|e| anyhow!("tag: {e}"))? {
            EntryTag::Plaintext(name, value) => tags.push((true, name, value)),
            EntryTag::Encrypted(name, value) => tags.push((false, name, value)),
        }
    }
    tags.sort();
    let mut hash = Sha256::new();
    let mut field = |bytes: &[u8]| {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    };
    field(&item.kind.to_be_bytes());
    field(category.as_bytes());
    field(name.as_bytes());
    field(value);
    for (plaintext, name, value) in tags {
        field(&[u8::from(plaintext)]);
        field(name.as_bytes());
        field(value.as_bytes());
    }
    field(
        item.expiry
            .map(|e| e.format(TIME_FORMAT).to_string())
            .unwrap_or_default()
            .as_bytes(),
    );
    Ok(hex::encode(hash.finalize()))
}

fn record_of(profile: &Profile, item: &InspectedItem) -> Result<Record> {
    let (Ok(category), Ok(name), Ok(value)) = (&item.category, &item.name, &item.value) else {
        bail!("The entry has decryption errors");
    };
    let mut tags = Vec::new();
    for tag in &item.tags {
        let (name, value, plaintext) = match tag.as_ref().map_err(|e| anyhow!("tag: {e}"))? {
            EntryTag::Plaintext(name, value) => (name, value, true),
            EntryTag::Encrypted(name, value) => (name, value, false),
        };
        tags.push(Tag {
            name: Some(name.clone()),
            value: Some(value.clone()),
            plaintext,
            error: None,
        });
    }
    tags.sort();
    Ok(Record {
        profile_id: profile.id,
        kind: item.kind,
        category: Some(category.clone()),
        name: Some(name.clone()),
        value: Some(value.to_vec()),
        expiry: item.expiry.map(|e| e.format(TIME_FORMAT).to_string()),
        damaged: false,
        tags,
    })
}

fn check_expiry(expiry: &Option<String>) -> Result<()> {
    if let Some(text) = expiry {
        NaiveDateTime::parse_from_str(text, TIME_FORMAT)
            .with_context(|| format!("Expiry must be UTC YYYY-MM-DD HH:MM:SS, not {text:?}"))?;
    }
    Ok(())
}

fn set_json(record: &mut Record, pointer: &str, new: &Value) -> Result<()> {
    let bytes = record.value.as_deref().unwrap_or_default();
    let mut document: Value =
        serde_json::from_slice(bytes).map_err(|_| anyhow!("The entry's value is not JSON"))?;
    if pointer.is_empty() {
        document = new.clone();
    } else {
        ensure!(
            pointer.starts_with('/'),
            "A JSON Pointer must be empty or start with '/'"
        );
        if let Some(target) = document.pointer_mut(pointer) {
            *target = new.clone();
        } else {
            let (parent, key) = pointer.rsplit_once('/').unwrap_or_default();
            let key = key.replace("~1", "/").replace("~0", "~");
            match document.pointer_mut(parent) {
                Some(Value::Object(map)) => {
                    map.insert(key, new.clone());
                }
                _ => bail!("Nothing at {pointer:?}, and its parent is not an existing object"),
            }
        }
    }
    record.value = Some(serde_json::to_vec(&document)?);
    Ok(())
}

fn find_tag(record: &Record, name: &str, plaintext: bool) -> Option<usize> {
    record
        .tags
        .iter()
        .position(|tag| tag.name.as_deref() == Some(name) && tag.plaintext == plaintext)
}

fn apply_ops(old: &Record, ops: &[&Op]) -> Result<Option<Record>> {
    let mut record = old.clone();
    for op in ops {
        match op {
            Op::Remove { .. } => {
                ensure!(
                    ops.len() == 1,
                    "Removing an entry cannot be combined with other edits to it"
                );
                return Ok(None);
            }
            Op::SetJson { pointer, value, .. } => set_json(&mut record, pointer, value)?,
            Op::SetTag {
                name,
                value,
                plaintext,
                ..
            } => {
                let tag = Tag {
                    name: Some(name.clone()),
                    value: Some(value.clone()),
                    plaintext: *plaintext,
                    error: None,
                };
                match find_tag(&record, name, *plaintext) {
                    Some(index) => record.tags[index] = tag,
                    None => record.tags.push(tag),
                }
            }
            Op::RemoveTag {
                name, plaintext, ..
            } => {
                let index = find_tag(&record, name, *plaintext).ok_or_else(|| {
                    anyhow!(
                        "The entry has no {} tag {name:?}",
                        if *plaintext { "plaintext" } else { "encrypted" }
                    )
                })?;
                record.tags.remove(index);
            }
            Op::SetExpiry { expiry, .. } => {
                check_expiry(expiry)?;
                record.expiry.clone_from(expiry);
            }
            Op::Insert { .. } => unreachable!("inserts are handled separately"),
        }
    }
    record.tags.sort();
    Ok(Some(record))
}

/// Edits resolved against the store.
#[derive(Debug)]
pub struct Plan {
    /// What would be written.
    pub(crate) changes: Vec<Change>,
    /// Profile names by id.
    pub profiles: HashMap<i64, String>,
    /// Fingerprints of the entries edited or removed.
    pub expected: Vec<Expected>,
    /// Edits that would change nothing (only reported when reviewing).
    pub notes: Vec<String>,
}

/// How strictly to resolve a plan.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Strictness {
    /// Proposal creation: check that edits are well formed, and reveal nothing else.
    Creating,
    /// Review and apply: also detect no-ops and name collisions, and verify fingerprints.
    Reviewing,
}

fn validate_request(ops: &[Op]) -> Result<()> {
    ensure!(!ops.is_empty(), "A proposal needs at least one edit");
    ensure!(
        ops.len() <= MAX_OPS,
        "A proposal can have at most {MAX_OPS} edits"
    );
    let mut bytes = 0;
    for op in ops {
        match op {
            Op::SetJson { value, .. } => bytes += value.to_string().len(),
            Op::Insert {
                value,
                category,
                name,
                tags,
                expiry,
                ..
            } => {
                ensure!(
                    !category.is_empty() && !name.is_empty(),
                    "An inserted entry needs a category and a name"
                );
                bytes += value.to_string().len();
                for tag in tags {
                    ensure!(!tag.name.is_empty(), "A tag needs a name");
                }
                check_expiry(expiry)?;
            }
            Op::SetTag { name, .. } | Op::RemoveTag { name, .. } => {
                ensure!(!name.is_empty(), "A tag needs a name");
            }
            _ => {}
        }
    }
    ensure!(
        bytes <= MAX_VALUE_BYTES,
        "The proposed values are too large"
    );
    Ok(())
}

/// Resolve edits against the current store.
pub async fn plan(
    source: &mut Source,
    ops: &[Op],
    expected: Option<&[Expected]>,
    strictness: Strictness,
) -> Result<Plan> {
    validate_request(ops)?;
    let profiles = source.select_profiles(None)?;
    let by_name: HashMap<&str, &Profile> = profiles.iter().map(|p| (p.name.as_str(), p)).collect();
    let profile_named = |name: &str| {
        by_name
            .get(name)
            .copied()
            .ok_or_else(|| anyhow!("Unknown profile {name:?}"))
    };

    let mut order: Vec<(&str, i64)> = Vec::new();
    let mut grouped: BTreeMap<(&str, i64), Vec<&Op>> = BTreeMap::new();
    for op in ops {
        if let Some(target) = op.target() {
            if !grouped.contains_key(&target) {
                order.push(target);
            }
            grouped.entry(target).or_default().push(op);
        }
    }

    let mut changes = Vec::new();
    let mut seen = Vec::new();
    let mut notes = Vec::new();
    for target in order {
        let (profile_name, id) = target;
        let profile = profile_named(profile_name)?;
        let item = source
            .fetch(profile, id)
            .await?
            .ok_or_else(|| anyhow!("No entry {id} in profile {profile_name:?}"))?;
        ensure!(
            item.kind == 2,
            "Entry {id} is a key-manager entry and cannot be changed here"
        );
        ensure!(
            item.expiry
                .is_none_or(|expiry| expiry > Utc::now().naive_utc()),
            "Entry {id} has expired and cannot be changed"
        );
        let fingerprint =
            fingerprint(&item).with_context(|| format!("Entry {id} cannot be read"))?;
        if let (Some(expected), Strictness::Reviewing) = (expected, strictness) {
            let matches = expected
                .iter()
                .any(|e| e.profile == profile_name && e.id == id && e.fingerprint == fingerprint);
            ensure!(
                matches,
                "Entry {id} in profile {profile_name:?} changed since the proposal was made"
            );
        }
        let old = record_of(profile, &item)?;
        let new =
            apply_ops(&old, &grouped[&target]).with_context(|| format!("Edit to entry {id}"))?;
        seen.push(Expected {
            profile: profile_name.to_owned(),
            id,
            fingerprint,
        });
        match new {
            None => changes.push(Change::Remove(old)),
            Some(new) if new == old => {
                if strictness == Strictness::Reviewing {
                    notes.push(format!(
                        "The edits to entry {id} in {profile_name:?} change nothing"
                    ));
                }
            }
            Some(new) => changes.push(Change::Replace(old, new)),
        }
    }

    for op in ops {
        let Op::Insert {
            profile,
            category,
            name,
            value,
            tags,
            expiry,
        } = op
        else {
            continue;
        };
        let profile = profile_named(profile)?;
        if strictness == Strictness::Reviewing {
            let existing = Query {
                kind: Some(2),
                category: Some(category.clone()),
                name: Some(name.clone()),
                ..Default::default()
            };
            ensure!(
                source.scan(profile, &existing, 0, 1).await?.is_empty(),
                "An entry named {name:?} already exists in category {category:?}"
            );
        }
        let mut tags: Vec<Tag> = tags
            .iter()
            .map(|tag| Tag {
                name: Some(tag.name.clone()),
                value: Some(tag.value.clone()),
                plaintext: tag.plaintext,
                error: None,
            })
            .collect();
        tags.sort();
        changes.push(Change::Insert(Record {
            profile_id: profile.id,
            kind: 2,
            category: Some(category.clone()),
            name: Some(name.clone()),
            value: Some(serde_json::to_vec(value)?),
            expiry: expiry.clone(),
            damaged: false,
            tags,
        }));
    }
    Ok(Plan {
        changes,
        profiles: profiles.iter().map(|p| (p.id, p.name.clone())).collect(),
        expected: seen,
        notes,
    })
}

/// Check a request against the store and save it for review.
pub async fn propose(
    source: &mut Source,
    store: &ProposalStore,
    request: ProposalRequest,
) -> Result<Proposal> {
    ensure!(!request.title.trim().is_empty(), "A proposal needs a title");
    ensure!(
        request.title.chars().count() <= MAX_TITLE,
        "The title is too long"
    );
    ensure!(
        request.rationale.chars().count() <= MAX_RATIONALE,
        "The rationale is too long"
    );
    let resolved = plan(source, &request.ops, None, Strictness::Creating).await?;
    let mut id = [0u8; 6];
    rand::rng().fill(&mut id);
    let proposal = Proposal {
        id: format!("p-{}", hex::encode(id)),
        created_at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        title: request.title.trim().to_owned(),
        rationale: request.rationale,
        status: Status::Pending,
        ops: request.ops,
        expected: resolved.expected,
    };
    store.create(&proposal)?;
    Ok(proposal)
}

fn show_value(bytes: &[u8]) -> String {
    match serde_json::from_slice::<Value>(bytes) {
        Ok(value) => serde_json::to_string_pretty(&value).unwrap_or_default(),
        Err(_) => match std::str::from_utf8(bytes) {
            Ok(text) => text.to_owned(),
            Err(_) => format!("<{} binary bytes>", bytes.len()),
        },
    }
}

fn show_tags(record: &Record) -> Vec<String> {
    record
        .tags
        .iter()
        .map(|tag| {
            format!(
                "{}{}={}",
                if tag.plaintext { "~" } else { "" },
                tag.name.as_deref().unwrap_or_default(),
                tag.value.as_deref().unwrap_or_default()
            )
        })
        .collect()
}

fn diff_lines(old: &str, new: &str, out: &mut String, indent: &str) {
    let diff = TextDiff::from_lines(old, new);
    let unified = diff.unified_diff().context_radius(2).to_string();
    for line in unified
        .lines()
        .filter(|line| !line.starts_with("---") && !line.starts_with("+++"))
    {
        out.push_str(indent);
        out.push_str(line);
        out.push('\n');
    }
}

/// Describe a change with the real before and after, for a person.
pub(crate) fn render(change: &Change, profiles: &HashMap<i64, String>) -> String {
    let mut out = String::new();
    let record = change.record();
    out.push_str(&format!(
        "{:<8}{}\n",
        change.label(),
        record.describe(profiles)
    ));
    match change {
        Change::Remove(old) => {
            out.push_str("  value removed:\n");
            diff_lines(
                &show_value(old.value.as_deref().unwrap_or_default()),
                "",
                &mut out,
                "    ",
            );
        }
        Change::Insert(new) => {
            out.push_str("  value:\n");
            diff_lines(
                "",
                &show_value(new.value.as_deref().unwrap_or_default()),
                &mut out,
                "    ",
            );
            for tag in show_tags(new) {
                out.push_str(&format!("  + tag {tag}\n"));
            }
            if let Some(expiry) = &new.expiry {
                out.push_str(&format!("  + expiry {expiry}\n"));
            }
        }
        Change::Replace(old, new) => {
            if old.value != new.value {
                out.push_str("  value:\n");
                diff_lines(
                    &show_value(old.value.as_deref().unwrap_or_default()),
                    &show_value(new.value.as_deref().unwrap_or_default()),
                    &mut out,
                    "    ",
                );
            }
            let (before, after) = (show_tags(old), show_tags(new));
            for tag in before.iter().filter(|tag| !after.contains(tag)) {
                out.push_str(&format!("  - tag {tag}\n"));
            }
            for tag in after.iter().filter(|tag| !before.contains(tag)) {
                out.push_str(&format!("  + tag {tag}\n"));
            }
            if old.expiry != new.expiry {
                out.push_str(&format!(
                    "  expiry {} -> {}\n",
                    old.expiry.as_deref().unwrap_or("(none)"),
                    new.expiry.as_deref().unwrap_or("(none)")
                ));
            }
        }
    }
    out
}

/// Print a proposal and the changes it would make now.
pub async fn review(
    store: &ProposalStore,
    id: &str,
    source: &mut Source,
    out: &mut (dyn Write + Send),
) -> Result<(Proposal, Plan)> {
    let proposal = store.load(id)?;
    writeln!(
        out,
        "Proposal {}  [{:?}]  {}",
        proposal.id, proposal.status, proposal.created_at
    )?;
    writeln!(out, "Title:     {}", proposal.title)?;
    if !proposal.rationale.is_empty() {
        writeln!(out, "Rationale: {}", proposal.rationale)?;
    }
    writeln!(out)?;
    if proposal.status != Status::Pending {
        writeln!(out, "This proposal is no longer pending.")?;
        let none = Plan {
            changes: Vec::new(),
            profiles: HashMap::new(),
            expected: Vec::new(),
            notes: Vec::new(),
        };
        return Ok((proposal, none));
    }
    let resolved = plan(
        source,
        &proposal.ops,
        Some(&proposal.expected),
        Strictness::Reviewing,
    )
    .await?;
    for change in &resolved.changes {
        writeln!(out, "{}", render(change, &resolved.profiles))?;
    }
    for note in &resolved.notes {
        writeln!(out, "note: {note}")?;
    }
    if resolved.changes.is_empty() {
        writeln!(out, "Nothing to apply.")?;
    }
    Ok((proposal, resolved))
}

/// Where and how to apply a proposal.
pub struct ApplyOptions<'a> {
    /// Connection used to read and check the store.
    pub read_uri: &'a str,
    /// Connection with permission to write; applying is refused without one.
    pub write_uri: Option<&'a str>,
    /// Environment variable holding the pass key.
    pub pass_key_env: Option<&'a str>,
    /// Write the changes; otherwise only review them.
    pub commit: bool,
    /// The person confirms that a recoverable backup exists.
    pub confirm_backup: bool,
}

/// Review a proposal and, when asked and confirmed, write it to the store.
///
/// `confirm` is shown the proposal id and must return true only when a person typed it.
pub async fn apply_proposal(
    store: &ProposalStore,
    id: &str,
    options: &ApplyOptions<'_>,
    out: &mut (dyn Write + Send),
    confirm: &mut (dyn FnMut(&str) -> Result<bool> + Send),
) -> Result<bool> {
    let status = store.load(id)?.status;
    ensure!(
        status == Status::Pending,
        "Proposal {id} is already {status:?}"
    );
    let mut source = Source::open(options.read_uri, options.pass_key_env).await?;
    let (proposal, resolved) = review(store, id, &mut source, out).await?;
    ensure!(
        proposal.status == Status::Pending,
        "Proposal {id} is already {:?}",
        proposal.status
    );
    if resolved.changes.is_empty() {
        return Ok(false);
    }
    if !options.commit {
        writeln!(
            out,
            "Dry run. To write {} change(s): changes apply {id} --commit --confirm-backup",
            resolved.changes.len()
        )?;
        return Ok(false);
    }
    ensure!(
        options.confirm_backup,
        "Pass --confirm-backup once a recoverable backup of the store exists"
    );
    let write_uri = options
        .write_uri
        .context("No write connection: set ASKAR_EXPLORER_WRITE_URI (a role allowed to write) to apply changes")?;
    let (key_reference, read_fingerprint) = apply::source_fingerprint(options.read_uri).await?;
    let (_, write_fingerprint) = apply::source_fingerprint(write_uri).await?;
    ensure!(
        read_fingerprint == write_fingerprint,
        "The write connection points at a different store than the read connection"
    );
    ensure!(confirm(&proposal.id)?, "Not confirmed; nothing was written");
    let pass_key = read_pass_key(&key_reference, options.pass_key_env)?;
    let backend = write_uri.open_backend(None, pass_key, None).await?;
    let result = apply::write_all(&backend, &resolved.changes, &resolved.profiles).await;
    use askar_storage::Backend;
    backend.close().await.ok();
    result?;
    store.finish(&proposal.id, Status::Applied)?;
    store.log(&format!(
        "applied {} changes={}",
        proposal.id,
        resolved.changes.len()
    ))?;
    writeln!(
        out,
        "Applied {} change(s) from {}.",
        resolved.changes.len(),
        proposal.id
    )?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(value: &str, tags: &[(&str, &str, bool)]) -> Record {
        Record {
            profile_id: 1,
            kind: 2,
            category: Some("c".into()),
            name: Some("n".into()),
            value: Some(value.as_bytes().to_vec()),
            expiry: None,
            damaged: false,
            tags: tags
                .iter()
                .map(|(name, value, plaintext)| Tag {
                    name: Some((*name).into()),
                    value: Some((*value).into()),
                    plaintext: *plaintext,
                    error: None,
                })
                .collect(),
        }
    }

    fn op(json: &str) -> Op {
        serde_json::from_str(json).unwrap()
    }

    fn text(record: &Record) -> String {
        String::from_utf8(record.value.clone().unwrap()).unwrap()
    }

    #[test]
    fn json_edits_keep_key_order_and_add_keys() {
        let old = record(r#"{"b":1,"a":{"x":[1,2]},"c":"z"}"#, &[]);
        let set = |pointer: &str, value: Value| Op::SetJson {
            profile: "p".into(),
            id: 1,
            pointer: pointer.into(),
            value,
        };
        let new = apply_ops(
            &old,
            &[
                &set("/a/x/1", json_value(9)),
                &set("/d", Value::Bool(true)),
                &set("/c", Value::Null),
            ],
        )
        .unwrap()
        .unwrap();
        assert_eq!(text(&new), r#"{"b":1,"a":{"x":[1,9]},"c":null,"d":true}"#);
        assert!(apply_ops(&old, &[&set("/missing/deep", json_value(1))]).is_err());
        assert!(apply_ops(&old, &[&set("no-slash", json_value(1))]).is_err());
        let whole = apply_ops(&old, &[&set("", json_value(5))])
            .unwrap()
            .unwrap();
        assert_eq!(text(&whole), "5");
        let escaped = record(r#"{"a/b":1}"#, &[]);
        let changed = apply_ops(&escaped, &[&set("/a~1b", json_value(2))])
            .unwrap()
            .unwrap();
        assert_eq!(text(&changed), r#"{"a/b":2}"#);
        assert!(apply_ops(&record("not json", &[]), &[&set("/a", json_value(1))]).is_err());
    }

    fn json_value(number: i64) -> Value {
        Value::from(number)
    }

    #[test]
    fn tag_and_expiry_edits() {
        let old = record("{}", &[("state", "active", true), ("owner", "x", false)]);
        let set_tag = op(
            r#"{"op":"set_tag","profile":"p","id":1,"name":"state","value":"done","plaintext":true}"#,
        );
        let add_tag = op(r#"{"op":"set_tag","profile":"p","id":1,"name":"new","value":"v"}"#);
        let drop_tag = op(r#"{"op":"remove_tag","profile":"p","id":1,"name":"owner"}"#);
        let new = apply_ops(&old, &[&set_tag, &add_tag, &drop_tag])
            .unwrap()
            .unwrap();
        let names: Vec<_> = new
            .tags
            .iter()
            .map(|t| {
                (
                    t.name.clone().unwrap(),
                    t.value.clone().unwrap(),
                    t.plaintext,
                )
            })
            .collect();
        assert_eq!(
            names,
            [
                ("new".into(), "v".into(), false),
                ("state".into(), "done".into(), true)
            ]
        );
        let missing = op(r#"{"op":"remove_tag","profile":"p","id":1,"name":"nope"}"#);
        assert!(apply_ops(&old, &[&missing]).is_err());
        let plain_vs_encrypted =
            op(r#"{"op":"remove_tag","profile":"p","id":1,"name":"owner","plaintext":true}"#);
        assert!(apply_ops(&old, &[&plain_vs_encrypted]).is_err());

        let expiry =
            op(r#"{"op":"set_expiry","profile":"p","id":1,"expiry":"2030-01-02 03:04:05"}"#);
        assert_eq!(
            apply_ops(&old, &[&expiry])
                .unwrap()
                .unwrap()
                .expiry
                .as_deref(),
            Some("2030-01-02 03:04:05")
        );
        let clear = op(r#"{"op":"set_expiry","profile":"p","id":1,"expiry":null}"#);
        assert_eq!(apply_ops(&old, &[&clear]).unwrap().unwrap().expiry, None);
        assert!(apply_ops(
            &old,
            &[&op(
                r#"{"op":"set_expiry","profile":"p","id":1,"expiry":"tomorrow"}"#
            )]
        )
        .is_err());
    }

    #[test]
    fn removal_cannot_be_combined() {
        let old = record("{}", &[]);
        let remove = op(r#"{"op":"remove","profile":"p","id":1}"#);
        assert!(apply_ops(&old, &[&remove]).unwrap().is_none());
        let tag = op(r#"{"op":"set_tag","profile":"p","id":1,"name":"a","value":"b"}"#);
        assert!(apply_ops(&old, &[&tag, &remove]).is_err());
    }

    #[test]
    fn requests_reject_unknown_fields_and_bad_shapes() {
        assert!(serde_json::from_str::<ProposalRequest>(
            r#"{"title":"t","ops":[],"status":"applied"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Op>(
            r#"{"op":"remove","profile":"p","id":1,"reveal":true}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Op>(r#"{"op":"apply","profile":"p","id":1}"#).is_err());
        assert!(validate_request(&[]).is_err());
        let many: Vec<Op> = (0..=MAX_OPS)
            .map(|i| op(&format!(r#"{{"op":"remove","profile":"p","id":{i}}}"#)))
            .collect();
        assert!(validate_request(&many).is_err());
        let huge = Op::SetJson {
            profile: "p".into(),
            id: 1,
            pointer: String::new(),
            value: Value::String("x".repeat(MAX_VALUE_BYTES)),
        };
        assert!(validate_request(&[huge]).is_err());
        assert!(validate_request(&[op(
            r#"{"op":"insert","profile":"p","category":"","name":"n","value":1}"#
        )])
        .is_err());
    }

    #[test]
    fn proposal_ids_cannot_escape_the_directory() {
        let store = ProposalStore::new("/nonexistent");
        for bad in [
            "../x",
            "p-../../etc",
            "p-0123456789a",
            "p-0123456789ab/",
            "P-0123456789ab",
            "",
        ] {
            assert!(store.load(bad).is_err(), "{bad}");
        }
        assert!(valid_id("p-0123456789ab"));
    }

    #[test]
    fn store_creates_private_files_limits_pending_and_finishes_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProposalStore::new(dir.path().join("proposals"));
        let make = |n: u8| Proposal {
            id: format!("p-{n:012x}"),
            created_at: format!("2026-01-01T00:00:{n:02}Z"),
            title: "t".into(),
            rationale: String::new(),
            status: Status::Pending,
            ops: vec![],
            expected: vec![],
        };
        store.create(&make(1)).unwrap();
        assert!(store.create(&make(1)).is_err(), "ids are not reused");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join("proposals/p-000000000001.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        store.finish("p-000000000001", Status::Applied).unwrap();
        assert!(store.finish("p-000000000001", Status::Rejected).is_err());
        assert_eq!(
            store.load("p-000000000001").unwrap().status,
            Status::Applied
        );
        for n in 2..(MAX_PENDING as u8 + 2) {
            store.create(&make(n)).unwrap();
        }
        assert!(store.create(&make(200)).is_err(), "too many waiting");
        assert_eq!(store.list().unwrap().len(), MAX_PENDING + 1);
        assert!(store
            .list()
            .unwrap()
            .windows(2)
            .all(|w| w[0].created_at <= w[1].created_at));
    }
}
