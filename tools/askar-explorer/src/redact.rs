//! Redaction for AI agents: structure and patterns are visible, data is not.
//!
//! A value is reduced to its JSON shape. Object keys that look like field names stay;
//! leaves become `<string:N>` or `<number>` unless the policy lists their path. Entry names
//! and tag values become keyed pseudonyms, so equal values can be matched without being
//! revealed. The pseudonym key never leaves the machine running the explorer.
//!
//! This is a guardrail, not encryption: it only protects data from a reader that cannot
//! run the explorer with the pass key itself.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use askar_storage::inspect::InspectedItem;
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::Sha256;

use crate::commands::value_text;

const DEFAULT_POLICY: &str = ".askar-explorer/policy.toml";
const KEY_FILE: &str = "pseudonym.key";
pub(crate) const MAX_DEPTH: usize = 8;
pub(crate) const MAX_ITEMS: usize = 20;
pub(crate) const MAX_KEYS: usize = 100;

/// Per-category additions to the global policy.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CategoryPolicy {
    /// JSON paths whose real values may be shown.
    #[serde(default)]
    pub show_paths: BTreeSet<String>,
    /// JSON paths whose string values are replaced by pseudonyms rather than lengths.
    #[serde(default)]
    pub pseudonymize_paths: BTreeSet<String>,
}

/// What agents may see beyond structure; empty by default.
///
/// Paths are dot-separated keys, `[]` for array elements, and `*` for an object key that
/// is not a field name, e.g. `state` or `participants[].role`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Plaintext or encrypted tag names whose values may be shown.
    #[serde(default)]
    pub show_tags: BTreeSet<String>,
    /// JSON paths whose real values may be shown, in every category.
    #[serde(default)]
    pub show_paths: BTreeSet<String>,
    /// JSON paths whose string values are replaced by pseudonyms, in every category.
    #[serde(default)]
    pub pseudonymize_paths: BTreeSet<String>,
    /// Object keys that are always treated as field names.
    #[serde(default)]
    pub safe_keys: BTreeSet<String>,
    /// Additions for specific categories.
    #[serde(default)]
    pub category: BTreeMap<String, CategoryPolicy>,
}

impl Policy {
    /// Parse a policy from TOML text.
    pub fn parse(text: &str) -> Result<Self> {
        toml::from_str(text).context("Invalid redaction policy")
    }

    /// Load a policy file; a missing file means the strictest policy.
    pub fn load(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(text) => Self::parse(&text).with_context(|| path.display().to_string()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error).with_context(|| format!("Cannot read {}", path.display())),
        }
    }

    /// Whether real values at this JSON path may be shown.
    pub fn shows_path(&self, category: &str, path: &str) -> bool {
        self.show_paths.contains(path)
            || self
                .category
                .get(category)
                .is_some_and(|policy| policy.show_paths.contains(path))
    }

    /// Whether values of this tag may be shown and searched.
    pub fn shows_tag(&self, name: &str) -> bool {
        self.show_tags.contains(name)
    }

    /// Whether an object key reads as a field name rather than data such as an identifier.
    pub fn is_structure_key(&self, key: &str) -> bool {
        if self.safe_keys.contains(key) {
            return true;
        }
        let mut chars = key.chars();
        let starts_like_a_name = chars
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_');
        let only_name_characters = chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        // Long mixed-case alphanumerics look like encoded identifiers, not field names.
        let looks_encoded = key.len() > 20
            && key.chars().any(|c| c.is_ascii_digit())
            && key.chars().any(|c| c.is_ascii_uppercase())
            && key.chars().any(|c| c.is_ascii_lowercase());
        starts_like_a_name && only_name_characters && key.len() <= 40 && !looks_encoded
    }

    fn pseudonymizes_path(&self, category: &str, path: &str) -> bool {
        self.pseudonymize_paths.contains(path)
            || self
                .category
                .get(category)
                .is_some_and(|policy| policy.pseudonymize_paths.contains(path))
    }
}

/// Turns store data into what an agent may see.
pub struct Redactor {
    policy: Policy,
    key: [u8; 32],
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Redactor(<redacted>)")
    }
}

impl Redactor {
    /// Use an explicit policy and pseudonym key.
    pub fn new(policy: Policy, key: [u8; 32]) -> Self {
        Self { policy, key }
    }

    /// Load the policy (default `.askar-explorer/policy.toml`) and the pseudonym key next to
    /// it, creating the key on first use.
    pub fn open(policy_path: Option<&Path>) -> Result<Self> {
        let path = policy_path.map_or_else(|| PathBuf::from(DEFAULT_POLICY), Path::to_path_buf);
        let policy = Policy::load(&path)?;
        let directory = path.parent().unwrap_or_else(|| Path::new("."));
        Ok(Self::new(
            policy,
            load_or_create_key(&directory.join(KEY_FILE))?,
        ))
    }

    /// The policy this redactor applies.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// A stable, keyed token standing in for a value.
    pub fn pseudonym(&self, value: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC accepts any key size");
        mac.update(b"askar-explorer/pseudonym/v1");
        mac.update(value.as_bytes());
        format!("p-{}", hex::encode(&mac.finalize().into_bytes()[..6]))
    }

    /// Whether the policy allows searching by this tag's value.
    pub fn shows_tag(&self, name: &str) -> bool {
        self.policy.shows_tag(name)
    }

    /// A tag value: real when the policy lists the tag, a pseudonym otherwise.
    pub fn tag_value(&self, name: &str, value: &str) -> Value {
        if self.shows_tag(name) {
            json!(value)
        } else {
            json!(self.pseudonym(value))
        }
    }

    /// An entry value reduced to its shape.
    pub fn value(&self, category: &str, bytes: &[u8]) -> Value {
        match std::str::from_utf8(bytes) {
            Ok(text) => match serde_json::from_str::<Value>(text) {
                Ok(json) => self.shape(category, &json, "", 0),
                Err(_) => json!(format!("<text:{} chars>", text.chars().count())),
            },
            Err(_) => json!(format!("<binary:{} bytes>", bytes.len())),
        }
    }

    fn shape(&self, category: &str, value: &Value, path: &str, depth: usize) -> Value {
        if depth > MAX_DEPTH {
            return json!("<…>");
        }
        match value {
            Value::Object(map) => {
                let mut shaped = Map::new();
                for (key, child) in map.iter().take(MAX_KEYS) {
                    let (shown, segment) = if self.policy.is_structure_key(key) {
                        (key.clone(), key.as_str())
                    } else {
                        (self.pseudonym(key), "*")
                    };
                    let child_path = if path.is_empty() {
                        segment.to_owned()
                    } else {
                        format!("{path}.{segment}")
                    };
                    shaped.insert(shown, self.shape(category, child, &child_path, depth + 1));
                }
                if map.len() > MAX_KEYS {
                    shaped.insert(
                        "…".into(),
                        json!(format!("<{} more keys>", map.len() - MAX_KEYS)),
                    );
                }
                Value::Object(shaped)
            }
            Value::Array(items) => {
                let child_path = format!("{path}[]");
                let mut shaped: Vec<Value> = items
                    .iter()
                    .take(MAX_ITEMS)
                    .map(|item| self.shape(category, item, &child_path, depth + 1))
                    .collect();
                if items.len() > MAX_ITEMS {
                    shaped.push(json!(format!("<{} more>", items.len() - MAX_ITEMS)));
                }
                Value::Array(shaped)
            }
            Value::String(text) => {
                if self.policy.shows_path(category, path) {
                    value.clone()
                } else if self.policy.pseudonymizes_path(category, path) {
                    json!(self.pseudonym(text))
                } else {
                    json!(format!("<string:{}>", text.chars().count()))
                }
            }
            Value::Number(_) => {
                if self.policy.shows_path(category, path) {
                    value.clone()
                } else {
                    json!("<number>")
                }
            }
            other => other.clone(),
        }
    }
}

fn load_or_create_key(path: &Path) -> Result<[u8; 32]> {
    match fs::read_to_string(path) {
        Ok(text) => {
            let bytes = hex::decode(text.trim())
                .with_context(|| format!("{} is not a hex key", path.display()))?;
            bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("{} must hold 32 bytes", path.display()))
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let mut key = [0u8; 32];
            rand::rng().fill(&mut key);
            if let Some(directory) = path.parent() {
                fs::create_dir_all(directory)?;
            }
            let mut create = OpenOptions::new();
            create.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                create.mode(0o600);
            }
            let mut file = create
                .open(path)
                .with_context(|| format!("Cannot create {}", path.display()))?;
            writeln!(file, "{}", hex::encode(key))?;
            Ok(key)
        }
        Err(error) => Err(error).with_context(|| format!("Cannot read {}", path.display())),
    }
}

/// How much of the store's data a command may show.
#[derive(Clone, Debug, Default)]
pub enum View {
    /// Structure only: values and tag values are withheld.
    #[default]
    Hidden,
    /// Shapes and pseudonyms, as allowed by a policy; safe to give to an agent.
    Redacted(Arc<Redactor>),
    /// Real data, for a person with the pass key. Key-manager values are still withheld.
    Reveal,
}

/// A tag as shown by a [`View`].
#[derive(Debug)]
pub struct ShownTag {
    /// Tag name.
    pub name: String,
    /// Whether the tag is stored in plaintext.
    pub plaintext: bool,
    /// The value, or null when the view withholds it.
    pub value: Value,
}

impl View {
    /// Whether this view is meant for an untrusted reader.
    pub fn is_redacted(&self) -> bool {
        matches!(self, Self::Redacted(_))
    }

    fn category(item: &InspectedItem) -> &str {
        item.category.as_deref().unwrap_or_default()
    }

    /// The entry name: real, or a pseudonym in a redacted view.
    pub fn name(&self, item: &InspectedItem) -> Value {
        match (&item.name, self) {
            (Err(_), _) => json!("<undecryptable>"),
            (Ok(name), Self::Redacted(redactor)) => json!(redactor.pseudonym(name)),
            (Ok(name), _) => json!(name),
        }
    }

    /// The entry value; null when withheld and always null for key-manager entries.
    pub fn value(&self, item: &InspectedItem) -> Value {
        if item.kind == 1 {
            return Value::Null;
        }
        match (self, &item.value) {
            (Self::Hidden, _) | (_, Err(_)) => Value::Null,
            (Self::Reveal, _) => value_text(item),
            (Self::Redacted(redactor), Ok(value)) => redactor.value(Self::category(item), value),
        }
    }

    /// The entry value as text, for SQL columns.
    ///
    /// A redacted value is always valid JSON, so `json_extract` returns NULL on rows that are
    /// not documents instead of failing the whole query.
    pub fn value_as_text(&self, item: &InspectedItem) -> Option<String> {
        match (self.value(item), self) {
            (Value::Null, _) => None,
            (Value::String(text), Self::Hidden | Self::Reveal) => Some(text),
            (other, _) => Some(other.to_string()),
        }
    }

    /// The decryptable tags of an entry.
    pub fn tags(&self, item: &InspectedItem) -> Vec<ShownTag> {
        use askar_storage::entry::EntryTag;
        item.tags
            .iter()
            .filter_map(|tag| tag.as_ref().ok())
            .map(|tag| {
                let (name, value, plaintext) = match tag {
                    EntryTag::Plaintext(name, value) => (name, value, true),
                    EntryTag::Encrypted(name, value) => (name, value, false),
                };
                let value = match self {
                    Self::Hidden => Value::Null,
                    Self::Reveal => json!(value),
                    Self::Redacted(redactor) => redactor.tag_value(name, value),
                };
                ShownTag {
                    name: name.clone(),
                    plaintext,
                    value,
                }
            })
            .collect()
    }

    /// Reject a name filter that would let a redacted reader test guesses.
    pub fn check_name_filter(&self) -> Result<()> {
        if self.is_redacted() {
            bail!("Names are pseudonyms in the redacted view, so name filters are not available");
        }
        Ok(())
    }

    /// Reject a tag filter on a tag whose values the policy does not show.
    pub fn check_tag_filter(&self, name: &str) -> Result<()> {
        match self {
            Self::Redacted(redactor) if !redactor.shows_tag(name) => bail!(
                "Tag {name:?} is not listed in show_tags, so it cannot be filtered in the redacted view"
            ),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redactor(policy: &str) -> Redactor {
        Redactor::new(Policy::parse(policy).unwrap(), [7; 32])
    }

    #[test]
    fn values_become_shapes() {
        let redactor = redactor("");
        let value = br#"{"token":"SECRET","count":3,"ok":true,"nested":{"list":["a","bb"]}}"#;
        assert_eq!(
            redactor.value("c", value),
            json!({
                "token": "<string:6>",
                "count": "<number>",
                "ok": true,
                "nested": {"list": ["<string:1>", "<string:2>"]}
            })
        );
    }

    #[test]
    fn policy_shows_and_pseudonymizes_listed_paths() {
        let redactor = redactor(
            r#"
            show_paths = ["state"]
            pseudonymize_paths = ["owner"]
            [category.records]
            show_paths = ["nested.list[]", "n"]
            "#,
        );
        let value =
            br#"{"state":"active","owner":"alice","n":5,"nested":{"list":["x"]},"other":"y"}"#;
        let shaped = redactor.value("records", value);
        assert_eq!(shaped["state"], "active");
        assert_eq!(shaped["n"], 5);
        assert_eq!(shaped["nested"]["list"], json!(["x"]));
        assert_eq!(shaped["other"], "<string:1>");
        let owner = shaped["owner"].as_str().unwrap();
        assert!(owner.starts_with("p-") && !owner.contains("alice"));
        // The category addition does not apply elsewhere.
        assert_eq!(redactor.value("other", value)["n"], "<number>");
        assert_eq!(redactor.value("other", value)["state"], "active");
    }

    #[test]
    fn identifier_like_keys_are_pseudonymized_and_matched_with_a_wildcard() {
        let redactor = redactor(r#"show_paths = ["*.status"]"#);
        let value =
            br#"{"did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc":{"status":"ok","secret":"s"}}"#;
        let text = redactor.value("c", value).to_string();
        assert!(!text.contains("did:peer") && !text.contains("Ez6LSb"));
        assert!(text.contains("\"status\":\"ok\"") && text.contains("<string:1>"));
        let uuid = br#"{"3fa85f64-5717-4562-b3fc-2c963f66afa6":1}"#;
        assert!(!redactor.value("c", uuid).to_string().contains("3fa85f64"));
        assert!(
            redactor.policy.is_structure_key("created_at")
                && redactor.policy.is_structure_key("connection-id")
        );
        let encoded = "Hq3VnLd8WfG2xT7yRk9Pb4Zc5Jm1Ns6AeUo";
        assert!(!redactor.policy.is_structure_key(encoded));
    }

    #[test]
    fn non_json_values_show_only_their_size() {
        let redactor = redactor("");
        assert_eq!(
            redactor.value("c", b"plain secret"),
            json!("<text:12 chars>")
        );
        assert_eq!(
            redactor.value("c", &[0xff, 0xfe, 1]),
            json!("<binary:3 bytes>")
        );
        assert_eq!(redactor.value("c", b"\"quoted\""), json!("<string:6>"));
    }

    #[test]
    fn large_documents_are_capped() {
        let redactor = redactor("");
        let list: Vec<i32> = (0..50).collect();
        let shaped = redactor.value("c", json!({ "list": list }).to_string().as_bytes());
        assert_eq!(shaped["list"].as_array().unwrap().len(), MAX_ITEMS + 1);
        let mut deep = json!("leaf");
        for _ in 0..20 {
            deep = json!({ "a": deep });
        }
        assert!(redactor
            .value("c", deep.to_string().as_bytes())
            .to_string()
            .contains("<…>"));
    }

    #[test]
    fn pseudonyms_are_stable_distinct_and_keyed() {
        let a = redactor("");
        let b = Redactor::new(Policy::default(), [8; 32]);
        assert_eq!(a.pseudonym("alice"), a.pseudonym("alice"));
        assert_ne!(a.pseudonym("alice"), a.pseudonym("bob"));
        assert_ne!(a.pseudonym("alice"), b.pseudonym("alice"));
        assert_eq!(a.tag_value("state", "x"), json!(a.pseudonym("x")));
        let shown = redactor(r#"show_tags = ["state"]"#);
        assert_eq!(shown.tag_value("state", "active"), json!("active"));
    }

    #[test]
    fn typos_in_the_policy_are_rejected() {
        assert!(Policy::parse("show_path = [\"x\"]").is_err());
        assert!(Policy::parse("[category.c]\nshow_tags = []").is_err());
    }

    #[test]
    fn key_file_is_created_once_with_private_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested").join("policy.toml");
        let first = Redactor::open(Some(&path)).unwrap();
        let second = Redactor::open(Some(&path)).unwrap();
        assert_eq!(first.pseudonym("x"), second.pseudonym("x"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path.parent().unwrap().join(KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        fs::write(path.parent().unwrap().join(KEY_FILE), "not hex").unwrap();
        assert!(Redactor::open(Some(&path)).is_err());
    }
}
