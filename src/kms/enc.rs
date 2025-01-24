pub use crate::crypto::buffer::SecretBytes;

/// The result of an AEAD encryption operation
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encrypted {
    pub(crate) buffer: SecretBytes,
    pub(crate) tag_pos: usize,
    pub(crate) nonce_pos: usize,
}

impl Encrypted {
    pub(crate) fn new(buffer: SecretBytes, tag_pos: usize, nonce_pos: usize) -> Self {
        Self {
            buffer,
            tag_pos,
            nonce_pos,
        }
    }

    /// Convert the ciphertext and tag into a Vec<u8>
    pub fn into_vec(self) -> Vec<u8> {
        self.buffer.into_vec()
    }

    /// Access the ciphertext
    pub fn ciphertext(&self) -> &[u8] {
        &self.buffer[0..(self.tag_pos)]
    }

    /// Access the nonce
    pub fn nonce(&self) -> &[u8] {
        &self.buffer[(self.nonce_pos)..]
    }

    /// Access the authentication tag
    pub fn tag(&self) -> &[u8] {
        &self.buffer[(self.tag_pos)..(self.nonce_pos)]
    }
}

impl AsRef<[u8]> for Encrypted {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl From<Encrypted> for SecretBytes {
    fn from(e: Encrypted) -> Self {
        e.buffer
    }
}

#[derive(Clone, Copy, Debug)]
/// The payload for an AEAD decryption operation
pub struct ToDecrypt<'d> {
    /// The ciphertext to decrypt
    pub ciphertext: &'d [u8],
    /// The separated AEAD tag, if any
    pub tag: &'d [u8],
}

impl ToDecrypt<'_> {
    /// Accessor for the combined length
    #[allow(clippy::len_without_is_empty)]
    #[inline]
    pub fn len(&self) -> usize {
        self.ciphertext.len() + self.tag.len()
    }

    pub(crate) fn into_secret(self) -> SecretBytes {
        if self.tag.is_empty() {
            SecretBytes::from_slice(self.ciphertext)
        } else {
            let mut buf = SecretBytes::with_capacity(self.len());
            buf.extend_from_slice(self.ciphertext);
            buf.extend_from_slice(self.tag);
            buf
        }
    }
}

impl<'d> From<&'d [u8]> for ToDecrypt<'d> {
    fn from(ciphertext: &'d [u8]) -> Self {
        Self {
            ciphertext,
            tag: &[],
        }
    }
}

impl<'d> From<(&'d [u8], &'d [u8])> for ToDecrypt<'d> {
    fn from(split: (&'d [u8], &'d [u8])) -> Self {
        Self {
            ciphertext: split.0,
            tag: split.1,
        }
    }
}

impl<'d> From<&'d Encrypted> for ToDecrypt<'d> {
    fn from(enc: &'d Encrypted) -> Self {
        Self {
            ciphertext: enc.ciphertext(),
            tag: enc.tag(),
        }
    }
}
