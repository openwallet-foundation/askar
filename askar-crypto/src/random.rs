//! Support for random number generation

use core::fmt::{self, Debug, Formatter};

use chacha20::{
    cipher::{KeyIvInit, KeySizeUser, StreamCipher},
    ChaCha20,
};
use core::convert::Infallible;

use rand::{CryptoRng, Rng as RngCore, SeedableRng, TryCryptoRng, TryRng};

use crate::array::{typenum::Unsigned, Array};

#[cfg(all(feature = "alloc", feature = "getrandom"))]
use crate::buffer::SecretBytes;
use crate::error::Error;

/// The expected length of a seed for `fill_random_deterministic`
pub const DETERMINISTIC_SEED_LENGTH: usize = <ChaCha20 as KeySizeUser>::KeySize::USIZE;

/// Combined trait for CryptoRng and RngCore
pub trait Rng: CryptoRng + RngCore + Debug {}

impl<T: CryptoRng + RngCore + Debug> Rng for T {}

/// A trait for generating raw key material, generally
/// cryptographically random bytes
pub trait KeyMaterial {
    /// Read key material from the generator
    fn read_okm(&mut self, buf: &mut [u8]);
}

impl<C: CryptoRng + RngCore> KeyMaterial for C {
    fn read_okm(&mut self, buf: &mut [u8]) {
        self.fill_bytes(buf);
    }
}

#[cfg(feature = "getrandom")]
#[cfg_attr(docsrs, doc(cfg(feature = "getrandom")))]
#[inline]
/// Obtain an instance of the default random number generator
pub fn default_rng() -> impl CryptoRng + Debug + Clone {
    #[cfg(feature = "std_rng")]
    {
        rand::rngs::ThreadRng::default()
    }
    #[cfg(not(feature = "std_rng"))]
    {
        rand::rand_core::UnwrapErr(rand::rngs::SysRng)
    }
}

/// Fill a mutable slice with random data using the
/// system random number generator.
#[cfg(feature = "getrandom")]
#[inline(always)]
pub fn fill_random(value: &mut [u8]) {
    default_rng().fill_bytes(value);
}

/// Written to be compatible with randombytes_deterministic in libsodium,
/// used to generate a deterministic symmetric encryption key
pub fn fill_random_deterministic(seed: &[u8], output: &mut [u8]) -> Result<(), Error> {
    RandomDet::new(seed).fill_bytes(output);
    Ok(())
}

/// A generator for deterministic random bytes
pub struct RandomDet {
    cipher: ChaCha20,
}

impl Debug for RandomDet {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "RandomDet {{}}")
    }
}

impl SeedableRng for RandomDet {
    type Seed = [u8; DETERMINISTIC_SEED_LENGTH];

    #[inline]
    fn from_seed(seed: Self::Seed) -> Self {
        Self {
            cipher: ChaCha20::new(&Array::from(seed), &Array::from(*b"LibsodiumDRG")),
        }
    }
}

impl TryCryptoRng for RandomDet {}

impl TryRng for RandomDet {
    type Error = Infallible;

    #[inline]
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0; 4];
        self.cipher.apply_keystream(&mut buf[..]);
        Ok(u32::from_le_bytes(buf))
    }

    #[inline]
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0; 8];
        self.cipher.apply_keystream(&mut buf[..]);
        Ok(u64::from_le_bytes(buf))
    }

    #[inline]
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        bytes.iter_mut().for_each(|b| *b = 0u8);
        self.cipher.apply_keystream(bytes);
        Ok(())
    }
}

impl RandomDet {
    /// Construct a new `RandomDet` instance from a seed value
    pub fn new(seed: &[u8]) -> Self {
        let mut sd = [0u8; DETERMINISTIC_SEED_LENGTH];
        let seed_len = seed.len().min(DETERMINISTIC_SEED_LENGTH);
        sd[..seed_len].copy_from_slice(&seed[..seed_len]);
        Self::from_seed(sd)
    }
}

#[cfg(all(feature = "alloc", feature = "getrandom"))]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
/// Create a new `SecretBytes` instance with random data.
#[inline(always)]
pub fn random_secret(len: usize) -> SecretBytes {
    SecretBytes::new_with(len, fill_random)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::HexRepr;
    use std::string::ToString;

    #[test]
    fn fill_random_det_expected() {
        let seed = b"testseed000000000000000000000001";
        let mut output = [0u8; 32];
        fill_random_deterministic(seed, &mut output).unwrap();
        assert_eq!(
            HexRepr(output).to_string(),
            "b1923a011cd1adbe89552db9862470c29512a8f51d184dfd778bfe7f845390d1"
        );
    }
}
