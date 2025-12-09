//! Supported key algorithms

use core::{
    fmt::{self, Debug, Display, Formatter},
    str::FromStr,
};

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use zeroize::Zeroize;

use crate::{
    backend::KeyBackend,
    buffer::{WriteBuffer, Writer},
    error::Error,
};

#[cfg(feature = "any_key")]
mod any;
#[cfg(feature = "any_key")]
#[cfg_attr(docsrs, doc(cfg(feature = "any_key")))]
pub use any::{AnyKey, AnyKeyCreate};

#[cfg(feature = "aes")]
#[cfg_attr(docsrs, doc(cfg(feature = "aes")))]
pub mod aes;

#[cfg(feature = "bls")]
#[cfg_attr(docsrs, doc(cfg(feature = "bls")))]
pub mod bls;

#[cfg(feature = "chacha")]
#[cfg_attr(docsrs, doc(cfg(feature = "chacha")))]
pub mod chacha20;

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
pub mod ed25519;

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
pub mod x25519;

#[cfg(feature = "ec_curves")]
mod ec_common;

#[cfg(feature = "k256")]
#[cfg_attr(docsrs, doc(cfg(feature = "k256")))]
pub mod k256;

#[cfg(feature = "p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
pub mod p256;

#[cfg(feature = "p384")]
#[cfg_attr(docsrs, doc(cfg(feature = "p384")))]
pub mod p384;

/// Supported key algorithms
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub enum KeyAlg {
    /// AES
    Aes(AesTypes),
    /// BLS12-381
    Bls12_381(BlsCurves),
    /// (X)ChaCha20-Poly1305
    Chacha20(Chacha20Types),
    /// Ed25519 signing key
    Ed25519,
    /// Curve25519 elliptic curve key exchange key
    X25519,
    /// Elliptic Curve key for signing or key exchange
    EcCurve(EcCurves),
}

impl KeyAlg {
    /// Get a reference to a string representing the `KeyAlg`
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aes(AesTypes::A128Gcm) => "a128gcm",
            Self::Aes(AesTypes::A256Gcm) => "a256gcm",
            Self::Aes(AesTypes::A128CbcHs256) => "a128cbchs256",
            Self::Aes(AesTypes::A256CbcHs512) => "a256cbchs512",
            Self::Aes(AesTypes::A128Kw) => "a128kw",
            Self::Aes(AesTypes::A256Kw) => "a256kw",
            Self::Bls12_381(BlsCurves::G1) => "bls12381g1",
            Self::Bls12_381(BlsCurves::G2) => "bls12381g2",
            Self::Chacha20(Chacha20Types::C20P) => "c20p",
            Self::Chacha20(Chacha20Types::XC20P) => "xc20p",
            Self::Ed25519 => "ed25519",
            Self::X25519 => "x25519",
            Self::EcCurve(EcCurves::Secp256k1) => "k256",
            Self::EcCurve(EcCurves::Secp256r1) => "p256",
            Self::EcCurve(EcCurves::Secp384r1) => "p384",
        }
    }
}

impl AsRef<str> for KeyAlg {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for KeyAlg {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match normalize_alg(s)? {
            a if a == "a128gcm" || a == "aes128gcm" => Ok(Self::Aes(AesTypes::A128Gcm)),
            a if a == "a256gcm" || a == "aes256gcm" => Ok(Self::Aes(AesTypes::A256Gcm)),
            a if a == "a128cbchs256" || a == "aes128cbchs256" => {
                Ok(Self::Aes(AesTypes::A128CbcHs256))
            }
            a if a == "a256cbchs512" || a == "aes256cbchs512" => {
                Ok(Self::Aes(AesTypes::A256CbcHs512))
            }
            a if a == "a128kw" || a == "aes128kw" => Ok(Self::Aes(AesTypes::A128Kw)),
            a if a == "a256kw" || a == "aes256kw" => Ok(Self::Aes(AesTypes::A256Kw)),
            a if a == "bls12381g1" => Ok(Self::Bls12_381(BlsCurves::G1)),
            a if a == "bls12381g2" => Ok(Self::Bls12_381(BlsCurves::G2)),
            a if a == "c20p" || a == "chacha20poly1305" => Ok(Self::Chacha20(Chacha20Types::C20P)),
            a if a == "xc20p" || a == "xchacha20poly1305" => {
                Ok(Self::Chacha20(Chacha20Types::XC20P))
            }
            a if a == "ed25519" => Ok(Self::Ed25519),
            a if a == "x25519" => Ok(Self::X25519),
            a if a == "k256" || a == "secp256k1" => Ok(Self::EcCurve(EcCurves::Secp256k1)),
            a if a == "p256" || a == "secp256r1" => Ok(Self::EcCurve(EcCurves::Secp256r1)),
            a if a == "p384" || a == "secp384r1" => Ok(Self::EcCurve(EcCurves::Secp384r1)),
            _ => Err(err_msg!(Unsupported, "Unknown key algorithm")),
        }
    }
}

#[inline(always)]
pub(crate) fn normalize_alg(alg: &str) -> Result<NormalizedAlg, Error> {
    NormalizedAlg::new(alg)
}

// Going through some hoops to avoid allocating.
// This struct stores up to 64 bytes of a normalized
// algorithm name in order to speed up comparisons
// when matching.
pub(crate) struct NormalizedAlg {
    len: usize,
    buf: [u8; 64],
}

impl NormalizedAlg {
    fn new(val: &str) -> Result<Self, Error> {
        let mut slf = Self {
            len: 0,
            buf: [0; 64],
        };
        let mut cu = [0u8; 4];
        let mut writer = Writer::from_slice(slf.buf.as_mut());
        for c in NormalizedIter::new(val) {
            let s = c.encode_utf8(&mut cu);
            writer.buffer_write(s.as_bytes())?;
        }
        slf.len = writer.position();
        Ok(slf)
    }
}

impl AsRef<[u8]> for NormalizedAlg {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl<T: AsRef<[u8]>> PartialEq<T> for NormalizedAlg {
    fn eq(&self, other: &T) -> bool {
        self.as_ref() == other.as_ref()
    }
}

struct NormalizedIter<'a> {
    chars: core::str::Chars<'a>,
}

impl<'a> NormalizedIter<'a> {
    pub fn new(val: &'a str) -> Self {
        Self { chars: val.chars() }
    }
}

impl Iterator for NormalizedIter<'_> {
    type Item = char;
    fn next(&mut self) -> Option<Self::Item> {
        #[allow(clippy::while_let_on_iterator)]
        while let Some(c) = self.chars.next() {
            if c != '-' && c != '_' && c != ' ' {
                return Some(c.to_ascii_lowercase());
            }
        }
        None
    }
}

impl Display for KeyAlg {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Supported algorithms for AES
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub enum AesTypes {
    /// 128-bit AES-GCM
    A128Gcm,
    /// 256-bit AES-GCM
    A256Gcm,
    /// 128-bit AES-CBC with HMAC-256
    A128CbcHs256,
    /// 256-bit AES-CBC with HMAC-512
    A256CbcHs512,
    /// 128-bit AES Key Wrap
    A128Kw,
    /// 256-bit AES Key Wrap
    A256Kw,
}

/// Supported public key types for Bls12_381
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub enum BlsCurves {
    /// G1 curve
    G1,
    /// G2 curve
    G2,
}

/// Supported algorithms for (X)ChaCha20-Poly1305
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub enum Chacha20Types {
    /// ChaCha20-Poly1305
    C20P,
    /// XChaCha20-Poly1305
    XC20P,
}

/// Supported curves for ECC operations
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub enum EcCurves {
    /// NIST P-256 curve
    Secp256r1,
    /// Koblitz 256 curve
    Secp256k1,
    /// NIST P-384 curve
    Secp384r1,
}

/// A trait for accessing the algorithm of a key, used when
/// converting to generic `AnyKey` instances.
pub trait HasKeyAlg: Debug {
    /// Get the corresponding key algorithm.
    fn algorithm(&self) -> KeyAlg;
}

/// A trait for accessing the backend of a key, used when
/// converting to generic `AnyKey` instances.
pub trait HasKeyBackend: Debug {
    /// Get the corresponding key backend.
    fn key_backend(&self) -> KeyBackend {
        KeyBackend::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmp_normalize() {
        assert!(normalize_alg("Test").unwrap() == "test");
        assert!(normalize_alg("t-e-s-t").unwrap() == "test");
        assert!(normalize_alg("--TE__ST--").unwrap() == "test");
        assert!(normalize_alg("t-e-s-t").unwrap() != "tes");
        assert!(normalize_alg("t-e-s-t").unwrap() != "testt");
    }
}
