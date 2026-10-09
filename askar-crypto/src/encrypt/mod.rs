//! AEAD encryption traits and parameters

use crate::{array::ArraySize, buffer::ResizeBuffer, error::Error};

#[cfg(feature = "getrandom")]
use crate::array::Array;

#[cfg(feature = "crypto_box")]
#[cfg_attr(docsrs, doc(cfg(feature = "crypto_box")))]
pub mod crypto_box;

/// Object-safe trait for key types which perform AEAD encryption
pub trait KeyAeadInPlace {
    /// Encrypt a secret value in place, appending the verification tag and
    /// returning the length of the ciphertext
    fn encrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<usize, Error>;

    /// Decrypt an encrypted (verification tag appended) value in place
    fn decrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error>;

    /// Get the nonce and tag length for encryption
    fn aead_params(&self) -> KeyAeadParams;

    /// Get the ciphertext padding required
    fn aead_padding(&self, _msg_len: usize) -> usize {
        0
    }
}

/// For concrete key types with fixed nonce and tag sizes
pub trait KeyAeadMeta {
    /// The size of the AEAD nonce
    type NonceSize: ArraySize;
    /// The size of the AEAD tag
    type TagSize: ArraySize;

    /// Generate a new random nonce
    #[cfg(feature = "getrandom")]
    fn random_nonce() -> Array<u8, Self::NonceSize> {
        let mut nonce = Array::default();
        crate::random::fill_random(nonce.as_mut_slice());
        nonce
    }
}

/// A structure combining the AEAD parameters
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyAeadParams {
    /// The length of the nonce
    pub nonce_length: usize,
    /// The length of the tag
    pub tag_length: usize,
}
