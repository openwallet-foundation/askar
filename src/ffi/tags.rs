use std::{borrow::Cow, fmt};

use serde::{
    de::{Error as SerdeError, MapAccess, SeqAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::entry::EntryTag;

/// A wrapper type used for managing (de)serialization of tags
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct EntryTagSet<'e>(Cow<'e, [EntryTag]>);

impl EntryTagSet<'_> {
    pub fn into_vec(self) -> Vec<EntryTag> {
        self.into()
    }
}

impl<'e> From<&'e [EntryTag]> for EntryTagSet<'e> {
    fn from(tags: &'e [EntryTag]) -> Self {
        Self(Cow::Borrowed(tags))
    }
}

impl From<Vec<EntryTag>> for EntryTagSet<'static> {
    fn from(tags: Vec<EntryTag>) -> Self {
        Self(Cow::Owned(tags))
    }
}

impl<'e> From<EntryTagSet<'e>> for Vec<EntryTag> {
    fn from(set: EntryTagSet<'e>) -> Self {
        set.0.into_owned()
    }
}

impl<'de> Deserialize<'de> for EntryTagSet<'static> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TagSetVisitor;

        impl<'d> Visitor<'d> for TagSetVisitor {
            type Value = EntryTagSet<'static>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object containing zero or more entry tags")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'d>,
            {
                let mut v = Vec::with_capacity(access.size_hint().unwrap_or_default());

                while let Some((key, values)) = access.next_entry::<&str, EntryTagValues>()? {
                    let (tag, enc) = match key.chars().next() {
                        Some('~') => (key[1..].to_owned(), false),
                        None => return Err(M::Error::custom("invalid tag name: empty string")),
                        _ => (key.to_owned(), true),
                    };
                    match (values, enc) {
                        (EntryTagValues::Single(value), true) => {
                            v.push(EntryTag::Encrypted(tag, value))
                        }
                        (EntryTagValues::Single(value), false) => {
                            v.push(EntryTag::Plaintext(tag, value))
                        }
                        (EntryTagValues::Multiple(values), true) => {
                            for value in values {
                                v.push(EntryTag::Encrypted(tag.clone(), value))
                            }
                        }
                        (EntryTagValues::Multiple(values), false) => {
                            for value in values {
                                v.push(EntryTag::Plaintext(tag.clone(), value))
                            }
                        }
                    }
                }

                Ok(EntryTagSet(Cow::Owned(v)))
            }
        }

        deserializer.deserialize_map(TagSetVisitor)
    }
}

enum EntryTagValues {
    Single(String),
    Multiple(Vec<String>),
}

impl<'de> Deserialize<'de> for EntryTagValues {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TagValuesVisitor;

        impl<'d> Visitor<'d> for TagValuesVisitor {
            type Value = EntryTagValues;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string or list of strings")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                Ok(EntryTagValues::Single(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                Ok(EntryTagValues::Single(value))
            }

            fn visit_seq<S>(self, mut access: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'d>,
            {
                let mut v = Vec::with_capacity(access.size_hint().unwrap_or_default());
                while let Some(value) = access.next_element()? {
                    v.push(value)
                }
                Ok(EntryTagValues::Multiple(v))
            }
        }

        deserializer.deserialize_any(TagValuesVisitor)
    }
}

impl Serialize for EntryTagSet<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use std::collections::BTreeMap;

        #[derive(PartialOrd, Ord)]
        struct TagName<'a>(&'a str, bool);

        impl PartialEq for TagName<'_> {
            fn eq(&self, other: &Self) -> bool {
                self.1 == other.1 && self.0 == other.0
            }
        }

        impl Eq for TagName<'_> {}

        impl Serialize for TagName<'_> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if self.1 {
                    serializer.serialize_str(self.0)
                } else {
                    serializer.collect_str(&format_args!("~{}", self.0))
                }
            }
        }

        let mut tags = BTreeMap::new();
        for tag in self.0.iter() {
            let (name, value) = match tag {
                EntryTag::Encrypted(name, val) => (TagName(name.as_str(), true), val.as_str()),
                EntryTag::Plaintext(name, val) => (TagName(name.as_str(), false), val.as_str()),
            };
            tags.entry(name).or_insert_with(Vec::new).push(value);
        }

        let mut map = serializer.serialize_map(Some(tags.len()))?;
        for (tag_name, values) in tags.into_iter() {
            if values.len() > 1 {
                map.serialize_entry(&tag_name, &values)?;
            } else {
                map.serialize_entry(&tag_name, &values[0])?;
            }
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_tags() {
        let tags = EntryTagSet::from(vec![
            EntryTag::Encrypted("a".to_owned(), "aval".to_owned()),
            EntryTag::Plaintext("b".to_owned(), "bval".to_owned()),
            EntryTag::Plaintext("b".to_owned(), "bval-2".to_owned()),
        ]);
        let ser = serde_json::to_string(&tags).unwrap();
        assert_eq!(ser, r#"{"a":"aval","~b":["bval","bval-2"]}"#);
        let tags2 = serde_json::from_str(&ser).unwrap();
        assert_eq!(tags, tags2);
    }
}
