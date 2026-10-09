use std::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

use digest::common::BlockSizeUser;
use hmac::{
    digest::{Digest, KeyInit},
    Mac, SimpleHmac,
};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{
        self,
        array::{typenum::Unsigned, Array, ArraySize},
        buffer::ArrayKey,
        kdf::KeyDerivation,
        random::KeyMaterial,
        repr::KeyGen,
    },
    error::Error,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(
    transparent,
    bound(
        deserialize = "ArrayKey<L>: for<'a> Deserialize<'a>",
        serialize = "ArrayKey<L>: Serialize"
    )
)]
pub struct HmacKey<H, L: ArraySize>(ArrayKey<L>, PhantomData<H>);

impl<H, L: ArraySize> HmacKey<H, L> {
    #[allow(dead_code)]
    pub fn from_slice(key: &[u8]) -> Result<Self, Error> {
        if key.len() != L::USIZE {
            return Err(err_msg!(Encryption, "invalid length for hmac key"));
        }
        Ok(Self(ArrayKey::from_slice(key), PhantomData))
    }
}

impl<H, L: ArraySize> AsRef<[u8]> for HmacKey<H, L> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<H, L: ArraySize> AsRef<Array<u8, L>> for HmacKey<H, L> {
    fn as_ref(&self) -> &Array<u8, L> {
        self.0.as_ref()
    }
}

impl<H, L: ArraySize> Debug for HmacKey<H, L> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if cfg!(test) {
            f.debug_tuple("HmacKey").field(&self.0).finish()
        } else {
            f.debug_tuple("HmacKey").field(&"<secret>").finish()
        }
    }
}

impl<H, L: ArraySize> PartialEq for HmacKey<H, L> {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}
impl<H, L: ArraySize> Eq for HmacKey<H, L> {}

impl<H, L: ArraySize> KeyGen for HmacKey<H, L> {
    fn generate(rng: impl KeyMaterial) -> Result<Self, crate::crypto::Error> {
        Ok(Self(ArrayKey::generate(rng), PhantomData))
    }
}

pub trait HmacDerive {
    type Hash: Digest + BlockSizeUser;
    type Key: AsRef<[u8]>;

    fn hmac_deriver<'d>(&'d self, inputs: &'d [&'d [u8]])
        -> HmacDeriver<'d, Self::Hash, Self::Key>;
}

impl<H, L: ArraySize> HmacDerive for HmacKey<H, L>
where
    H: Digest + BlockSizeUser,
{
    type Hash = H;
    type Key = Self;

    #[inline]
    fn hmac_deriver<'d>(
        &'d self,
        inputs: &'d [&'d [u8]],
    ) -> HmacDeriver<'d, Self::Hash, Self::Key> {
        HmacDeriver {
            key: self,
            inputs,
            _marker: PhantomData,
        }
    }
}

pub struct HmacDeriver<'d, H, K: ?Sized> {
    key: &'d K,
    inputs: &'d [&'d [u8]],
    _marker: PhantomData<H>,
}

impl<H, K> KeyDerivation for HmacDeriver<'_, H, K>
where
    K: AsRef<[u8]> + ?Sized,
    H: Digest + BlockSizeUser,
{
    fn derive_key_bytes(&mut self, key_output: &mut [u8]) -> Result<(), crypto::Error> {
        if key_output.len() > H::OutputSize::USIZE {
            return Err(crypto::Error::from_msg(
                crypto::ErrorKind::Encryption,
                "invalid length for hmac output",
            ));
        }
        let mut hmac = SimpleHmac::<H>::new_from_slice(self.key.as_ref()).map_err(|_| {
            crypto::Error::from_msg(crypto::ErrorKind::Encryption, "invalid length for hmac key")
        })?;
        for msg in self.inputs {
            hmac.update(msg);
        }
        let hash = hmac.finalize().into_bytes();
        key_output.copy_from_slice(&hash[..key_output.len()]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::array::typenum::U32;
    use sha2::Sha256;

    #[test]
    fn hmac_expected() {
        let key = HmacKey::<Sha256, U32>::from_slice(&hex!(
            "c32ef97a2eed6316ae9b0d3129554358980ee6e0b21b81625229c191a3469f7e"
        ))
        .unwrap();
        let mut output = [0u8; 12];
        key.hmac_deriver(&[b"test message"])
            .derive_key_bytes(&mut output)
            .unwrap();
        assert_eq!(output, &hex!("4cecfbf6be721395529be686")[..]);
    }
}
