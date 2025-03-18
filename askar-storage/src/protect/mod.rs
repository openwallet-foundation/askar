//! Storage encryption

use std::{collections::HashMap, sync::Arc};

use async_lock::RwLock;

pub mod kdf;

pub mod hmac_key;

mod pass_key;
pub use self::pass_key::PassKey;

mod profile_key;
pub use self::profile_key::ProfileKey;

mod store_key;
pub use self::store_key::{generate_raw_store_key, StoreKey, StoreKeyMethod, StoreKeyReference};

use crate::{
    crypto::buffer::SecretBytes,
    entry::{EncEntryTag, EntryTag},
    error::Error,
    future::unblock,
};

pub type ProfileId = i64;

#[derive(Debug)]
pub struct KeyCache {
    profile_info: RwLock<HashMap<String, (ProfileId, Arc<ProfileKey>)>>,
    pub(crate) store_key: Arc<StoreKey>,
}

impl KeyCache {
    pub fn new(store_key: impl Into<Arc<StoreKey>>) -> Self {
        Self {
            profile_info: RwLock::new(HashMap::new()),
            store_key: store_key.into(),
        }
    }

    pub async fn load_key(&self, ciphertext: Vec<u8>) -> Result<ProfileKey, Error> {
        let store_key = self.store_key.clone();
        unblock(move || {
            let data = store_key
                .unwrap_data(ciphertext)
                .map_err(err_map!(Encryption, "Error decrypting profile key"))?;
            ProfileKey::from_slice(data.as_ref())
        })
        .await
    }

    pub fn add_profile_mut(&mut self, ident: String, pid: ProfileId, key: ProfileKey) {
        self.profile_info
            .get_mut()
            .insert(ident, (pid, Arc::new(key)));
    }

    pub async fn add_profile(&self, ident: String, pid: ProfileId, key: Arc<ProfileKey>) {
        self.profile_info.write().await.insert(ident, (pid, key));
    }

    pub async fn get_profile(&self, name: &str) -> Option<(ProfileId, Arc<ProfileKey>)> {
        self.profile_info.read().await.get(name).cloned()
    }

    pub async fn clear_profile(&self, name: &str) {
        self.profile_info.write().await.remove(name);
    }
}

pub(crate) trait EntryEncryptor {
    fn prepare_input(input: &[u8]) -> SecretBytes {
        SecretBytes::from(input)
    }

    fn encrypt_entry_category(&self, category: SecretBytes) -> Result<Vec<u8>, Error>;
    fn encrypt_entry_name(&self, name: SecretBytes) -> Result<Vec<u8>, Error>;
    fn encrypt_entry_value(
        &self,
        category: &[u8],
        name: &[u8],
        value: SecretBytes,
    ) -> Result<Vec<u8>, Error>;
    fn encrypt_entry_tags(&self, tags: Vec<EntryTag>) -> Result<Vec<EncEntryTag>, Error>;

    fn decrypt_entry_category(&self, enc_category: Vec<u8>) -> Result<String, Error>;
    fn decrypt_entry_name(&self, enc_name: Vec<u8>) -> Result<String, Error>;
    fn decrypt_entry_value(
        &self,
        category: &[u8],
        name: &[u8],
        enc_value: Vec<u8>,
    ) -> Result<SecretBytes, Error>;
    fn decrypt_entry_tags(&self, enc_tags: Vec<EncEntryTag>) -> Result<Vec<EntryTag>, Error>;
}

pub struct NullEncryptor;

impl EntryEncryptor for NullEncryptor {
    fn encrypt_entry_category(&self, category: SecretBytes) -> Result<Vec<u8>, Error> {
        Ok(category.into_vec())
    }
    fn encrypt_entry_name(&self, name: SecretBytes) -> Result<Vec<u8>, Error> {
        Ok(name.into_vec())
    }
    fn encrypt_entry_value(
        &self,
        _category: &[u8],
        _name: &[u8],
        value: SecretBytes,
    ) -> Result<Vec<u8>, Error> {
        Ok(value.into_vec())
    }
    fn encrypt_entry_tags(&self, tags: Vec<EntryTag>) -> Result<Vec<EncEntryTag>, Error> {
        Ok(tags
            .into_iter()
            .map(|tag| match tag {
                EntryTag::Encrypted(name, value) => EncEntryTag {
                    name: name.into_bytes(),
                    value: value.into_bytes(),
                    plaintext: false,
                },
                EntryTag::Plaintext(name, value) => EncEntryTag {
                    name: name.into_bytes(),
                    value: value.into_bytes(),
                    plaintext: true,
                },
            })
            .collect())
    }

    fn decrypt_entry_category(&self, enc_category: Vec<u8>) -> Result<String, Error> {
        String::from_utf8(enc_category).map_err(err_map!(Encryption))
    }
    fn decrypt_entry_name(&self, enc_name: Vec<u8>) -> Result<String, Error> {
        String::from_utf8(enc_name).map_err(err_map!(Encryption))
    }
    fn decrypt_entry_value(
        &self,
        _category: &[u8],
        _name: &[u8],
        enc_value: Vec<u8>,
    ) -> Result<SecretBytes, Error> {
        Ok(enc_value.into())
    }
    fn decrypt_entry_tags(&self, enc_tags: Vec<EncEntryTag>) -> Result<Vec<EntryTag>, Error> {
        enc_tags.into_iter().try_fold(vec![], |mut acc, tag| {
            let name = String::from_utf8(tag.name).map_err(err_map!(Encryption))?;
            let value = String::from_utf8(tag.value).map_err(err_map!(Encryption))?;
            acc.push(if tag.plaintext {
                EntryTag::Plaintext(name, value)
            } else {
                EntryTag::Encrypted(name, value)
            });
            Result::<_, Error>::Ok(acc)
        })
    }
}
