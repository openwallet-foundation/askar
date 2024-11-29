//! AES key representations with AEAD support

use core::fmt::{self, Debug, Formatter};

use aead::{generic_array::ArrayLength, AeadCore, AeadInPlace, KeyInit, KeySizeUser};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{AesTypes, HasKeyAlg, HasKeyBackend, KeyAlg};
use crate::{
    buffer::{ArrayKey, ResizeBuffer, Writer},
    encrypt::{KeyAeadInPlace, KeyAeadMeta, KeyAeadParams},
    error::Error,
    generic_array::{typenum::Unsigned, GenericArray},
    jwk::{FromJwk, JwkEncoder, JwkParts, ToJwk},
    kdf::{FromKeyDerivation, FromKeyExchange, KeyDerivation, KeyExchange},
    random::KeyMaterial,
    repr::{KeyGen, KeyMeta, KeySecretBytes},
};

mod cbc_hmac;
pub use cbc_hmac::{A128CbcHs256, A256CbcHs512};

mod key_wrap;
pub use key_wrap::{A128Kw, A256Kw};

/// The 'kty' value of a symmetric key JWK
pub static JWK_KEY_TYPE: &str = "oct";

/// Trait implemented by supported AES authenticated encryption algorithms
pub trait AesType: 'static {
    /// The size of the key secret bytes
    type KeySize: ArrayLength<u8>;

    /// The associated algorithm type
    const ALG_TYPE: AesTypes;
    /// The associated JWK algorithm name
    const JWK_ALG: &'static str;
}

type KeyType<A> = ArrayKey<<A as AesType>::KeySize>;

type NonceSize<A> = <A as KeyAeadMeta>::NonceSize;

type TagSize<A> = <A as KeyAeadMeta>::TagSize;

/// An AES symmetric encryption key
#[derive(Serialize, Deserialize, Zeroize)]
#[serde(
    transparent,
    bound(
        deserialize = "KeyType<T>: for<'a> Deserialize<'a>",
        serialize = "KeyType<T>: Serialize"
    )
)]
// SECURITY: ArrayKey is zeroized on drop
pub struct AesKey<T: AesType>(KeyType<T>);

impl<T: AesType> Clone for AesKey<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: AesType> Debug for AesKey<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesKey")
            .field("alg", &T::JWK_ALG)
            .field("key", &self.0)
            .finish()
    }
}

impl<T: AesType> PartialEq for AesKey<T> {
    fn eq(&self, other: &Self) -> bool {
        other.0 == self.0
    }
}

impl<T: AesType> Eq for AesKey<T> {}

impl<T: AesType> HasKeyBackend for AesKey<T> {}

impl<T: AesType> HasKeyAlg for AesKey<T> {
    fn algorithm(&self) -> KeyAlg {
        KeyAlg::Aes(T::ALG_TYPE)
    }
}

impl<T: AesType> KeyMeta for AesKey<T> {
    type KeySize = T::KeySize;
}

impl<T: AesType> KeyGen for AesKey<T> {
    fn generate(rng: impl KeyMaterial) -> Result<Self, Error> {
        Ok(AesKey(KeyType::<T>::generate(rng)))
    }
}

impl<T: AesType> KeySecretBytes for AesKey<T> {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        if key.len() != KeyType::<T>::SIZE {
            return Err(err_msg!(InvalidKeyData));
        }
        Ok(Self(KeyType::<T>::from_slice(key)))
    }

    fn with_secret_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        f(Some(self.0.as_ref()))
    }
}

impl<T: AesType> FromKeyDerivation for AesKey<T> {
    fn from_key_derivation<D: KeyDerivation>(mut derive: D) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(Self(KeyType::<T>::try_new_with(|arr| {
            derive.derive_key_bytes(arr)
        })?))
    }
}

impl<T: AesType> FromJwk for AesKey<T> {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        if jwk.kty != JWK_KEY_TYPE {
            return Err(err_msg!(InvalidKeyData, "Unsupported key type"));
        }
        if jwk.alg != T::JWK_ALG {
            return Err(err_msg!(InvalidKeyData, "Unsupported key algorithm"));
        }
        Ok(Self(ArrayKey::try_new_with(|buf| {
            if jwk.k.decode_base64(buf)? != buf.len() {
                Err(err_msg!(InvalidKeyData))
            } else {
                Ok(())
            }
        })?))
    }
}

impl<T: AesType> ToJwk for AesKey<T> {
    fn encode_jwk(&self, enc: &mut dyn JwkEncoder) -> Result<(), Error> {
        if enc.is_public() {
            return Err(err_msg!(Unsupported, "Cannot export as a public key"));
        }
        if !enc.is_thumbprint() {
            enc.add_str("alg", T::JWK_ALG)?;
        }
        enc.add_as_base64("k", self.0.as_ref())?;
        enc.add_str("kty", JWK_KEY_TYPE)?;
        Ok(())
    }
}

// for direct key agreement (not used currently)
impl<Lhs, Rhs, T> FromKeyExchange<Lhs, Rhs> for AesKey<T>
where
    Lhs: KeyExchange<Rhs> + ?Sized,
    Rhs: ?Sized,
    T: AesType,
{
    fn from_key_exchange(lhs: &Lhs, rhs: &Rhs) -> Result<Self, Error> {
        Ok(Self(KeyType::<T>::try_new_with(|arr| {
            let mut buf = Writer::from_slice(arr);
            lhs.write_key_exchange(rhs, &mut buf)?;
            if buf.position() != T::KeySize::USIZE {
                return Err(err_msg!(Usage, "Invalid length for key exchange output"));
            }
            Ok(())
        })?))
    }
}

/// 128 bit AES-GCM
pub type A128Gcm = Aes128Gcm;

impl AesType for A128Gcm {
    type KeySize = <Self as KeySizeUser>::KeySize;

    const ALG_TYPE: AesTypes = AesTypes::A128Gcm;
    const JWK_ALG: &'static str = "A128GCM";
}

/// 256 bit AES-GCM
pub type A256Gcm = Aes256Gcm;

impl AesType for A256Gcm {
    type KeySize = <Self as KeySizeUser>::KeySize;

    const ALG_TYPE: AesTypes = AesTypes::A256Gcm;
    const JWK_ALG: &'static str = "A256GCM";
}

// generic implementation applying to AesGcm
impl<T: AeadCore + AesType> KeyAeadMeta for AesKey<T> {
    type NonceSize = <T as AeadCore>::NonceSize;
    type TagSize = <T as AeadCore>::TagSize;
}

// generic implementation applying to AesGcm
impl<T> KeyAeadInPlace for AesKey<T>
where
    T: KeyInit + AeadInPlace + AesType<KeySize = <T as KeySizeUser>::KeySize>,
{
    /// Encrypt a secret value in place, appending the verification tag
    fn encrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<usize, Error> {
        if nonce.len() != T::NonceSize::USIZE {
            return Err(err_msg!(InvalidNonce));
        }
        let enc = <T as KeyInit>::new(self.0.as_ref());
        let tag = enc
            .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buffer.as_mut())
            .map_err(|_| err_msg!(Encryption, "AEAD encryption error"))?;
        let ctext_len = buffer.as_ref().len();
        buffer.buffer_write(&tag[..])?;
        Ok(ctext_len)
    }

    /// Decrypt an encrypted (verification tag appended) value in place
    fn decrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error> {
        if nonce.len() != T::NonceSize::USIZE {
            return Err(err_msg!(InvalidNonce));
        }
        let buf_len = buffer.as_ref().len();
        if buf_len < T::TagSize::USIZE {
            return Err(err_msg!(Encryption, "Invalid size for encrypted data"));
        }
        let tag_start = buf_len - T::TagSize::USIZE;
        let mut tag = GenericArray::default();
        tag.clone_from_slice(&buffer.as_ref()[tag_start..]);
        let enc = <T as KeyInit>::new(self.0.as_ref());
        enc.decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            aad,
            &mut buffer.as_mut()[..tag_start],
            &tag,
        )
        .map_err(|_| err_msg!(Encryption, "AEAD decryption error"))?;
        buffer.buffer_resize(tag_start)?;
        Ok(())
    }

    fn aead_params(&self) -> KeyAeadParams {
        KeyAeadParams {
            nonce_length: T::NonceSize::USIZE,
            tag_length: T::TagSize::USIZE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::SecretBytes;
    use crate::repr::ToSecretBytes;

    #[test]
    fn encrypt_round_trip() {
        fn test_encrypt<T>()
        where
            T: AesType,
            AesKey<T>: KeyAeadInPlace + KeyAeadMeta,
        {
            let input = b"hello";
            let aad = b"additional data";
            let key = AesKey::<T>::random().unwrap();
            let mut buffer = SecretBytes::from_slice(input);
            let params = key.aead_params();
            let pad_len = key.aead_padding(input.len());
            let nonce = AesKey::<T>::random_nonce();
            key.encrypt_in_place(&mut buffer, &nonce, aad).unwrap();
            let enc_len = buffer.len();
            assert_eq!(enc_len, input.len() + pad_len + params.tag_length);
            assert_ne!(&buffer[..], input);
            let mut dec = buffer.clone();
            key.decrypt_in_place(&mut dec, &nonce, aad).unwrap();
            assert_eq!(&dec[..], input);

            // test tag validation
            buffer.as_mut()[enc_len - 1] = buffer.as_mut()[enc_len - 1].wrapping_add(1);
            assert!(key.decrypt_in_place(&mut buffer, &nonce, aad).is_err());
        }
        test_encrypt::<A128Gcm>();
        test_encrypt::<A256Gcm>();
        test_encrypt::<A128CbcHs256>();
        test_encrypt::<A256CbcHs512>();
    }

    #[test]
    fn test_random() {
        let key = AesKey::<A128CbcHs256>::random().unwrap();
        let nonce = AesKey::<A128CbcHs256>::random_nonce();
        let message = b"hello there";
        let mut buffer = [0u8; 255];
        buffer[0..message.len()].copy_from_slice(&message[..]);
        let mut writer = Writer::from_slice_position(&mut buffer, message.len());
        key.encrypt_in_place(&mut writer, nonce.as_slice(), &[])
            .unwrap();
    }

    #[test]
    fn serialize_round_trip() {
        fn test_serialize<T: AesType>() {
            let key = AesKey::<T>::random().unwrap();
            let sk = key.to_secret_bytes().unwrap();
            let mut bytes = alloc::vec::Vec::new();
            ciborium::into_writer(&key, &mut bytes).unwrap();
            let deser: alloc::vec::Vec<u8> = ciborium::from_reader(&bytes[..]).unwrap();
            assert_eq!(deser, sk.as_ref());
        }
        test_serialize::<A128Gcm>();
        test_serialize::<A256Gcm>();
        test_serialize::<A128CbcHs256>();
        test_serialize::<A256CbcHs512>();
        test_serialize::<A128Kw>();
        test_serialize::<A256Kw>();
    }
}
