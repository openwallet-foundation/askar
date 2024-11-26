use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::hmac_key::{HmacDerive, HmacKey};
use super::EntryEncryptor;
use crate::{
    crypto::{
        alg::chacha20::{Chacha20Key, C20P},
        buffer::{ArrayKey, ResizeBuffer, SecretBytes, WriteBuffer},
        encrypt::{KeyAeadInPlace, KeyAeadMeta},
        generic_array::typenum::{Unsigned, U32},
        kdf::FromKeyDerivation,
        repr::KeyGen,
    },
    entry::{EncEntryTag, EntryTag},
    error::Error,
};

pub type ProfileKey = ProfileKeyImpl<Chacha20Key<C20P>, HmacKey<Sha256, U32>>;

/// A record combining the keys required to encrypt and decrypt storage entries
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(bound(
    deserialize = "Key: for<'a> Deserialize<'a>, HmacKey: for<'a> Deserialize<'a>",
    serialize = "Key: Serialize, HmacKey: Serialize"
))]
#[serde(tag = "ver", rename = "1")]
pub struct ProfileKeyImpl<Key, HmacKey> {
    #[serde(rename = "ick")]
    pub category_key: Key,
    #[serde(rename = "ink")]
    pub name_key: Key,
    #[serde(rename = "ihk")]
    pub item_hmac_key: HmacKey,
    #[serde(rename = "tnk")]
    pub tag_name_key: Key,
    #[serde(rename = "tvk")]
    pub tag_value_key: Key,
    #[serde(rename = "thk")]
    pub tags_hmac_key: HmacKey,
}

impl<Key, HmacKey> ProfileKeyImpl<Key, HmacKey>
where
    Key: KeyGen,
    HmacKey: KeyGen,
{
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            category_key: KeyGen::random()?,
            name_key: KeyGen::random()?,
            item_hmac_key: KeyGen::random()?,
            tag_name_key: KeyGen::random()?,
            tag_value_key: KeyGen::random()?,
            tags_hmac_key: KeyGen::random()?,
        })
    }
}

impl<Key, HmacKey> ProfileKeyImpl<Key, HmacKey>
where
    Key: Serialize + for<'de> Deserialize<'de>,
    HmacKey: Serialize + for<'de> Deserialize<'de>,
{
    pub fn to_bytes(&self) -> Result<SecretBytes, Error> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes)
            .map_err(err_map!(Unexpected, "Error serializing profile key"))?;

        Ok(SecretBytes::from(bytes))
    }

    pub fn from_slice(input: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(input).map_err(err_map!(Unsupported, "Invalid profile key"))
    }
}

impl<Key, HmacKey> ProfileKeyImpl<Key, HmacKey>
where
    Key: KeyAeadInPlace + KeyAeadMeta + FromKeyDerivation,
    HmacKey: HmacDerive,
{
    fn encrypted_size(len: usize) -> usize {
        len + Key::NonceSize::USIZE + Key::TagSize::USIZE
    }

    /// Encrypt a value with a predictable nonce, making it searchable
    fn encrypt_searchable(
        mut buffer: SecretBytes,
        enc_key: &Key,
        hmac_key: &HmacKey,
    ) -> Result<Vec<u8>, Error> {
        let nonce = ArrayKey::<Key::NonceSize>::from_key_derivation(
            hmac_key.hmac_deriver(&[buffer.as_ref()]),
        )?;
        enc_key.encrypt_in_place(&mut buffer, nonce.as_ref(), &[])?;
        buffer.buffer_insert(0, nonce.as_ref())?;
        Ok(buffer.into_vec())
    }

    fn encrypt(mut buffer: SecretBytes, enc_key: &Key) -> Result<Vec<u8>, Error> {
        let nonce = ArrayKey::<Key::NonceSize>::random();
        enc_key.encrypt_in_place(&mut buffer, nonce.as_ref(), &[])?;
        buffer.buffer_insert(0, nonce.as_ref())?;
        Ok(buffer.into_vec())
    }

    fn decrypt(ciphertext: Vec<u8>, enc_key: &Key) -> Result<SecretBytes, Error> {
        let nonce_len = Key::NonceSize::USIZE;
        if ciphertext.len() < nonce_len {
            return Err(err_msg!(Encryption, "invalid encrypted value"));
        }
        let mut buffer = SecretBytes::from(ciphertext);
        let nonce = ArrayKey::<Key::NonceSize>::from_slice(&buffer.as_ref()[..nonce_len]);
        buffer.buffer_remove(0..nonce_len)?;
        enc_key.decrypt_in_place(&mut buffer, nonce.as_ref(), &[])?;
        Ok(buffer)
    }

    #[inline]
    fn derive_value_key(&self, category: &[u8], name: &[u8]) -> Result<Key, Error> {
        Ok(Key::from_key_derivation(self.item_hmac_key.hmac_deriver(
            &[
                &(category.len() as u32).to_be_bytes(),
                category,
                &(name.len() as u32).to_be_bytes(),
                name,
            ],
        ))?)
    }

    pub fn encrypt_tag_name(&self, name: SecretBytes) -> Result<Vec<u8>, Error> {
        Self::encrypt_searchable(name, &self.tag_name_key, &self.tags_hmac_key)
    }

    pub fn encrypt_tag_value(&self, value: SecretBytes) -> Result<Vec<u8>, Error> {
        Self::encrypt_searchable(value, &self.tag_value_key, &self.tags_hmac_key)
    }

    pub fn decrypt_tag_name(&self, enc_tag_name: Vec<u8>) -> Result<SecretBytes, Error> {
        Self::decrypt(enc_tag_name, &self.tag_name_key)
    }

    pub fn decrypt_tag_value(&self, enc_tag_value: Vec<u8>) -> Result<SecretBytes, Error> {
        Self::decrypt(enc_tag_value, &self.tag_value_key)
    }
}

impl<Key: PartialEq, HmacKey: PartialEq> PartialEq for ProfileKeyImpl<Key, HmacKey> {
    fn eq(&self, other: &Self) -> bool {
        self.category_key == other.category_key
            && self.name_key == other.name_key
            && self.item_hmac_key == other.item_hmac_key
            && self.tag_name_key == other.tag_name_key
            && self.tag_value_key == other.tag_value_key
            && self.tags_hmac_key == other.tags_hmac_key
    }
}
impl<Key: PartialEq, HmacKey: PartialEq> Eq for ProfileKeyImpl<Key, HmacKey> {}

impl<Key, HmacKey> EntryEncryptor for ProfileKeyImpl<Key, HmacKey>
where
    Key: KeyAeadInPlace + KeyAeadMeta + FromKeyDerivation,
    HmacKey: HmacDerive,
{
    fn prepare_input(input: &[u8]) -> SecretBytes {
        let mut buf = SecretBytes::with_capacity(Self::encrypted_size(input.len()));
        buf.buffer_write(input).unwrap();
        buf
    }

    fn encrypt_entry_category(&self, category: SecretBytes) -> Result<Vec<u8>, Error> {
        Self::encrypt_searchable(category, &self.category_key, &self.item_hmac_key)
    }

    fn encrypt_entry_name(&self, name: SecretBytes) -> Result<Vec<u8>, Error> {
        Self::encrypt_searchable(name, &self.name_key, &self.item_hmac_key)
    }

    fn encrypt_entry_value(
        &self,
        category: &[u8],
        name: &[u8],
        value: SecretBytes,
    ) -> Result<Vec<u8>, Error> {
        let value_key = self.derive_value_key(category, name)?;
        Self::encrypt(value, &value_key)
    }

    fn decrypt_entry_category(&self, enc_category: Vec<u8>) -> Result<String, Error> {
        decode_utf8(Self::decrypt(enc_category, &self.category_key)?.into_vec())
    }

    fn decrypt_entry_name(&self, enc_name: Vec<u8>) -> Result<String, Error> {
        decode_utf8(Self::decrypt(enc_name, &self.name_key)?.into_vec())
    }

    fn decrypt_entry_value(
        &self,
        category: &[u8],
        name: &[u8],
        enc_value: Vec<u8>,
    ) -> Result<SecretBytes, Error> {
        let value_key = self.derive_value_key(category, name)?;
        Self::decrypt(enc_value, &value_key)
    }

    fn encrypt_entry_tags(&self, tags: Vec<EntryTag>) -> Result<Vec<EncEntryTag>, Error> {
        tags.into_iter()
            .map(|tag| match tag {
                EntryTag::Plaintext(name, value) => {
                    let name = self.encrypt_tag_name(name.into())?;
                    Ok(EncEntryTag {
                        name,
                        value: value.into_bytes(),
                        plaintext: true,
                    })
                }
                EntryTag::Encrypted(name, value) => {
                    let name = self.encrypt_tag_name(name.into())?;
                    let value = self.encrypt_tag_value(value.into())?;
                    Ok(EncEntryTag {
                        name,
                        value,
                        plaintext: false,
                    })
                }
            })
            .collect()
    }

    fn decrypt_entry_tags(&self, enc_tags: Vec<EncEntryTag>) -> Result<Vec<EntryTag>, Error> {
        enc_tags.into_iter().try_fold(vec![], |mut acc, tag| {
            let name = decode_utf8(self.decrypt_tag_name(tag.name)?.into_vec())?;
            acc.push(if tag.plaintext {
                let value = decode_utf8(tag.value)?;
                EntryTag::Plaintext(name, value)
            } else {
                let value = decode_utf8(self.decrypt_tag_value(tag.value)?.into_vec())?;
                EntryTag::Encrypted(name, value)
            });
            Result::Ok(acc)
        })
    }
}

#[inline(always)]
fn decode_utf8(value: Vec<u8>) -> Result<String, Error> {
    String::from_utf8(value).map_err(err_map!(Encryption))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Entry, EntryKind};

    #[test]
    fn encrypt_entry_round_trip() {
        let key = ProfileKey::new().unwrap();
        let test_record = Entry::new(
            EntryKind::Item,
            "category",
            "name",
            "value",
            vec![
                EntryTag::Plaintext("plain".to_string(), "tag".to_string()),
                EntryTag::Encrypted("enctag".to_string(), "envtagval".to_string()),
            ],
        );
        let enc_category = key
            .encrypt_entry_category(test_record.category.clone().into())
            .unwrap();
        let enc_name = key
            .encrypt_entry_name(test_record.name.clone().into())
            .unwrap();
        let enc_value = key
            .encrypt_entry_value(
                test_record.category.as_bytes(),
                test_record.name.as_bytes(),
                test_record.value.clone(),
            )
            .unwrap();
        let enc_tags = key.encrypt_entry_tags(test_record.tags.clone()).unwrap();
        assert_ne!(test_record.category.as_bytes(), &enc_category[..]);
        assert_ne!(test_record.name.as_bytes(), &enc_name[..]);
        assert_ne!(test_record.value, enc_value);

        let cmp_record = Entry::new(
            EntryKind::Item,
            key.decrypt_entry_category(enc_category).unwrap(),
            key.decrypt_entry_name(enc_name).unwrap(),
            key.decrypt_entry_value(
                test_record.category.as_bytes(),
                test_record.name.as_bytes(),
                enc_value,
            )
            .unwrap(),
            key.decrypt_entry_tags(enc_tags).unwrap(),
        );
        assert_eq!(test_record, cmp_record);
    }

    #[test]
    fn check_encrypt_searchable() {
        let input = SecretBytes::from(&b"hello"[..]);
        let key = Chacha20Key::<C20P>::random().unwrap();
        let hmac_key = HmacKey::random().unwrap();
        let enc1 = ProfileKey::encrypt_searchable(input.clone(), &key, &hmac_key).unwrap();
        let enc2 = ProfileKey::encrypt_searchable(input.clone(), &key, &hmac_key).unwrap();
        let enc3 = ProfileKey::encrypt(input.clone(), &key).unwrap();
        assert_eq!(&enc1, &enc2);
        assert_ne!(&enc1, &enc3);
        let dec = ProfileKey::decrypt(enc1, &key).unwrap();
        assert_eq!(dec, input);
    }

    #[test]
    fn serialize_round_trip() {
        let key = ProfileKey::new().unwrap();
        let mut key_cbor = Vec::new();
        ciborium::into_writer(&key, &mut key_cbor).unwrap();
        let key_cmp = ciborium::from_reader(&key_cbor[..]).unwrap();
        assert_eq!(key, key_cmp);
    }
}
