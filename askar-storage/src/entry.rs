//! Entry type definitions

use std::{
    fmt::{self, Debug, Formatter},
    pin::Pin,
    str::FromStr,
};

use futures_lite::stream::{Stream, StreamExt};
use zeroize::Zeroize;

use super::wql;
use crate::{crypto::buffer::SecretBytes, error::Error};

pub(crate) fn sorted_tags(tags: &[EntryTag]) -> Vec<&EntryTag> {
    if tags.is_empty() {
        Vec::new()
    } else {
        let mut tags = tags.iter().collect::<Vec<&EntryTag>>();
        tags.sort();
        tags
    }
}

/// A record in the store
#[derive(Clone, Debug, Eq)]
pub struct Entry {
    /// The entry kind discriminator
    pub kind: EntryKind,

    /// The category of the entry record
    pub category: String,

    /// The name of the entry record, unique within its category
    pub name: String,

    /// The value of the entry record
    pub value: SecretBytes,

    /// Tags associated with the entry record
    pub tags: Vec<EntryTag>,
}

impl Entry {
    /// Create a new `Entry`
    #[inline]
    pub fn new<C: Into<String>, N: Into<String>, V: Into<SecretBytes>>(
        kind: EntryKind,
        category: C,
        name: N,
        value: V,
        tags: Vec<EntryTag>,
    ) -> Self {
        Self {
            kind,
            category: category.into(),
            name: name.into(),
            value: value.into(),
            tags,
        }
    }

    pub(crate) fn sorted_tags(&self) -> Vec<&EntryTag> {
        sorted_tags(&self.tags)
    }
}

impl PartialEq for Entry {
    fn eq(&self, rhs: &Self) -> bool {
        self.category == rhs.category
            && self.name == rhs.name
            && self.value == rhs.value
            && self.sorted_tags() == rhs.sorted_tags()
    }
}

/// Set of distinct entry kinds for separating records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// Key manager entry
    Kms = 1,
    /// General stored item
    Item = 2,
}

impl TryFrom<usize> for EntryKind {
    type Error = Error;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Kms),
            2 => Ok(Self::Item),
            _ => Err(err_msg!("Unknown entry kind: {value}")),
        }
    }
}

/// Supported operations for entries in the store
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryOperation {
    /// Insert a new `Entry`
    Insert,
    /// Replace an existing `Entry`
    Replace,
    /// Remove an existing `Entry`
    Remove,
}

/// A tag on an entry record in the store
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Zeroize)]
pub enum EntryTag {
    /// An entry tag to be stored encrypted
    Encrypted(String, String),
    /// An entry tag to be stored in plaintext (for ordered comparison)
    Plaintext(String, String),
}

impl EntryTag {
    /// Accessor for the tag name
    pub fn name(&self) -> &str {
        match self {
            Self::Encrypted(name, _) | Self::Plaintext(name, _) => name,
        }
    }

    /// Create a new EntryTag using references to the name and value
    pub fn map_ref(&self, f: impl FnOnce(&str, &str) -> (String, String)) -> Self {
        match self {
            Self::Encrypted(name, val) => {
                let (name, val) = f(name.as_str(), val.as_str());
                Self::Encrypted(name, val)
            }
            Self::Plaintext(name, val) => {
                let (name, val) = f(name.as_str(), val.as_str());
                Self::Plaintext(name, val)
            }
        }
    }

    /// Setter for the tag name
    pub fn update_name(&mut self, f: impl FnOnce(&mut String)) {
        match self {
            Self::Encrypted(name, _) | Self::Plaintext(name, _) => f(name),
        }
    }

    /// Accessor for the tag value
    pub fn value(&self) -> &str {
        match self {
            Self::Encrypted(_, val) | Self::Plaintext(_, val) => val,
        }
    }

    /// Unwrap the tag value
    pub fn into_value(self) -> String {
        match self {
            Self::Encrypted(_, value) | Self::Plaintext(_, value) => value,
        }
    }
}

impl Debug for EntryTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encrypted(name, value) => f
                .debug_tuple("Encrypted")
                .field(&name)
                .field(&value)
                .finish(),
            Self::Plaintext(name, value) => f
                .debug_tuple("Plaintext")
                .field(&name)
                .field(&value)
                .finish(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EncEntryTag {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub plaintext: bool,
}

/// A WQL filter used to restrict record queries
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct TagFilter {
    pub(crate) query: wql::Query,
}

impl TagFilter {
    /// Combine multiple tag filters using the `AND` operator
    #[inline]
    pub fn all_of(each: Vec<TagFilter>) -> Self {
        Self {
            query: wql::Query::And(unsafe {
                std::mem::transmute::<Vec<TagFilter>, Vec<wql::Query>>(each)
            }),
        }
    }

    /// Combine multiple tag filters using the `OR` operator
    #[inline]
    pub fn any_of(each: Vec<TagFilter>) -> Self {
        Self {
            query: wql::Query::Or(unsafe {
                std::mem::transmute::<Vec<TagFilter>, Vec<wql::Query>>(each)
            }),
        }
    }

    /// Get the inverse of a tag filter
    #[inline]
    pub fn negate(filter: TagFilter) -> Self {
        Self {
            query: wql::Query::Not(Box::new(filter.query)),
        }
    }

    /// Create an equality comparison tag filter
    #[inline]
    pub fn is_eq(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Eq(name.into(), value.into()),
        }
    }

    /// Create an inequality comparison tag filter
    #[inline]
    pub fn is_not_eq(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Neq(name.into(), value.into()),
        }
    }

    /// Create an greater-than comparison tag filter
    #[inline]
    pub fn is_gt(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Gt(name.into(), value.into()),
        }
    }

    /// Create an greater-than-or-equal comparison tag filter
    #[inline]
    pub fn is_gte(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Gte(name.into(), value.into()),
        }
    }

    /// Create an less-than comparison tag filter
    #[inline]
    pub fn is_lt(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Lt(name.into(), value.into()),
        }
    }

    /// Create an less-than-or-equal comparison tag filter
    #[inline]
    pub fn is_lte(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Lte(name.into(), value.into()),
        }
    }

    /// Create a LIKE comparison tag filter
    #[inline]
    pub fn is_like(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Like(name.into(), value.into()),
        }
    }

    /// Create an IN comparison tag filter for a set of tag values
    #[inline]
    pub fn is_in(name: impl Into<String>, values: Vec<String>) -> Self {
        Self {
            query: wql::Query::In(name.into(), values),
        }
    }

    /// Create an EXISTS tag filter for a set of tag names
    #[inline]
    pub fn exist(names: Vec<String>) -> Self {
        Self {
            query: wql::Query::Exist(names),
        }
    }

    /// Convert the tag filter to JSON format
    pub fn to_string(&self) -> Result<String, Error> {
        serde_json::to_string(&self.query).map_err(err_map!("Error encoding tag filter"))
    }

    /// Unwrap into a wql::Query
    pub fn into_query(self) -> wql::Query {
        self.query
    }
}

impl From<wql::Query> for TagFilter {
    fn from(query: wql::Query) -> Self {
        Self { query }
    }
}

impl FromStr for TagFilter {
    type Err = Error;

    fn from_str(query: &str) -> Result<Self, Error> {
        let query = serde_json::from_str(query).map_err(err_map!("Error parsing tag query"))?;
        Ok(Self { query })
    }
}

/// An active record scan of a store backend
pub struct Scan<'s, T> {
    #[allow(clippy::type_complexity)]
    stream: Option<Pin<Box<dyn Stream<Item = Result<Vec<T>, Error>> + Send + 's>>>,
    page_size: usize,
}

impl<'s, T> Scan<'s, T> {
    pub(crate) fn new<S>(stream: S, page_size: usize) -> Self
    where
        S: Stream<Item = Result<Vec<T>, Error>> + Send + 's,
    {
        Self {
            stream: Some(stream.boxed()),
            page_size,
        }
    }

    /// Fetch the next set of result rows
    pub async fn fetch_next(&mut self) -> Result<Option<Vec<T>>, Error> {
        if let Some(mut s) = self.stream.take() {
            match s.try_next().await? {
                Some(val) => {
                    if val.len() == self.page_size {
                        self.stream.replace(s);
                    }
                    Ok(Some(val))
                }
                None => Ok(None),
            }
        } else {
            Ok(None)
        }
    }
}

impl<S> Debug for Scan<'_, S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scan")
            .field("page_size", &self.page_size)
            .finish()
    }
}
