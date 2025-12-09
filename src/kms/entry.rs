use super::local_key::LocalKey;
use crate::{
    crypto::{alg::AnyKey, buffer::SecretBytes, jwk::FromJwk},
    entry::{Entry, EntryTag},
    error::Error,
};

/// Key reference variant
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum KeyReference {
    /// Any other reference as fallback
    Any(String),
}

impl From<&str> for KeyReference {
    fn from(value: &str) -> Self {
        Self::Any(String::from(value))
    }
}

impl From<KeyReference> for String {
    fn from(key_reference: KeyReference) -> Self {
        match key_reference {
            KeyReference::Any(s) => s,
        }
    }
}

/// Parameters defining a stored key
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct KeyParams {
    /// Associated key metadata
    #[serde(default, rename = "meta", skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,

    /// An optional external reference for the key
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<KeyReference>,

    /// The associated key data
    /// - Stored as a JWK for software-backed keys
    /// - Stored as a key id for hardware-backed keys
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<SecretBytes>,
}

impl KeyParams {
    pub(crate) fn to_bytes(&self) -> Result<SecretBytes, Error> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes)
            .map_err(|e| err_msg!(Unexpected, "Error serializing key params: {}", e))?;

        Ok(SecretBytes::from(bytes))
    }

    pub(crate) fn from_slice(params: &[u8]) -> Result<KeyParams, Error> {
        ciborium::from_reader(params)
            .map_err(|e| err_msg!(Unexpected, "Error deserializing key params: {}", e))
    }
}

/// A stored key entry
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEntry {
    /// The key entry identifier
    pub(crate) name: String,
    /// The parameters defining the key
    pub(crate) params: KeyParams,
    /// Key algorithm
    pub(crate) alg: Option<String>,
    /// Thumbprints for the key
    pub(crate) thumbprints: Vec<String>,
    /// Thumbprints for the key
    pub(crate) tags: Vec<EntryTag>,
}

impl KeyEntry {
    /// Accessor for the key identity
    pub fn algorithm(&self) -> Option<&str> {
        self.alg.as_ref().map(String::as_ref)
    }

    /// Accessor for the stored key metadata
    pub fn metadata(&self) -> Option<&str> {
        self.params.metadata.as_ref().map(String::as_ref)
    }

    /// Accessor for the key identity
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Accessor for the key tags
    pub fn tags_as_slice(&self) -> &[EntryTag] {
        self.tags.as_slice()
    }

    /// Determine if a key entry refers to a local or external key
    pub fn is_local(&self) -> bool {
        self.params.reference.is_none()
    }

    pub(crate) fn from_entry(entry: Entry) -> Result<Self, Error> {
        let params = KeyParams::from_slice(&entry.value)?;
        let mut alg = None;
        let mut thumbprints = Vec::new();
        let mut tags = entry.tags;
        let mut idx = 0;
        while idx < tags.len() {
            let tag = &mut tags[idx];
            let name = tag.name();
            if name.starts_with("user:") {
                tag.update_name(|tag| tag.replace_range(0..5, ""));
                idx += 1;
            } else if name == "alg" {
                alg.replace(tags.remove(idx).into_value());
            } else if name == "thumb" {
                thumbprints.push(tags.remove(idx).into_value());
            } else {
                // unrecognized tag
                tags.remove(idx).into_value();
            }
        }
        // keep sorted for checking equality
        thumbprints.sort();
        tags.sort();
        Ok(Self {
            name: entry.name,
            params,
            alg,
            thumbprints,
            tags,
        })
    }

    /// Create a local key instance from this key storage entry
    pub fn load_local_key(&self) -> Result<LocalKey, Error> {
        if let Some(key_data) = self.params.data.as_ref() {
            Ok(LocalKey {
                inner: Box::<AnyKey>::from_jwk_slice(key_data.as_ref())?,
                ephemeral: false,
            })
        } else {
            Err(err_msg!("Missing key data"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_params_roundtrip() {
        let params = KeyParams {
            metadata: Some("meta".to_string()),
            reference: None,
            data: Some(SecretBytes::from(vec![0, 0, 0, 0])),
        };
        let enc_params = params.to_bytes().unwrap();
        let p2 = KeyParams::from_slice(&enc_params).unwrap();
        assert_eq!(p2, params);
    }
}
