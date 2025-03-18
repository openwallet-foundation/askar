//! Signature traits and parameters

use core::str::FromStr;

#[cfg(feature = "alloc")]
use crate::buffer::SecretBytes;
use crate::{alg::normalize_alg, buffer::WriteBuffer, error::Error};

/// Signature creation operations
pub trait KeySign: KeySigVerify {
    /// Create a signature of the requested type and write it to the
    /// provided buffer.
    fn write_signature(
        &self,
        message: &[u8],
        sig_type: Option<SignatureType>,
        out: &mut dyn WriteBuffer,
    ) -> Result<(), Error>;

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    /// Create a signature of the requested type and return an allocated
    /// buffer.
    fn create_signature(
        &self,
        message: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<SecretBytes, Error> {
        let mut buf = SecretBytes::with_capacity(128);
        self.write_signature(message, sig_type, &mut buf)?;
        Ok(buf)
    }
}

/// Signature verification operations
pub trait KeySigVerify {
    /// Check the validity of signature over a message with the
    /// specified signature type.
    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<bool, Error>;
}

/// Supported signature types
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureType {
    /// Standard signature output for ed25519
    EdDSA,
    /// Elliptic curve DSA using P-256 and SHA-256
    ES256,
    /// Elliptic curve DSA using P-256 and pre-hashed input
    ES256ph,
    /// Elliptic curve DSA using K-256 and SHA-256
    ES256K,
    /// Elliptic curve DSA using K-256 and pre-hashed input
    ES256Kph,
    /// Elliptic curve DSA using P-384 and SHA-384
    ES384,
    /// Elliptic curve DSA using P-384 and pre-hashed input
    ES384ph,
}

impl FromStr for SignatureType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match normalize_alg(s)? {
            a if a == "eddsa" => Ok(Self::EdDSA),
            a if a == "es256" => Ok(Self::ES256),
            a if a == "es256ph" => Ok(Self::ES256ph),
            a if a == "es256k" => Ok(Self::ES256K),
            a if a == "es256kph" => Ok(Self::ES256Kph),
            a if a == "es384" => Ok(Self::ES384),
            a if a == "es384ph" => Ok(Self::ES384ph),
            _ => Err(err_msg!(Unsupported, "Unknown signature algorithm")),
        }
    }
}

impl SignatureType {
    /// Get the length of the signature output.
    pub const fn signature_length(&self) -> usize {
        match self {
            Self::EdDSA | Self::ES256 | Self::ES256ph | Self::ES256K | Self::ES256Kph => 64,
            Self::ES384 | Self::ES384ph => 96,
        }
    }
}
