use core::{
    array::TryFromSliceError,
    fmt::{self, Debug, Formatter},
    hash,
    marker::{PhantomData, PhantomPinned},
    ops::Deref,
};

use crate::array::{Array, ArraySize};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use super::HexRepr;
use crate::{
    error::Error,
    kdf::{FromKeyDerivation, KeyDerivation},
    random::KeyMaterial,
};

/// A secure representation for fixed-length keys
#[derive(Clone)]
#[repr(transparent)]
pub struct ArrayKey<L: ArraySize>(
    Array<u8, L>,
    // ensure that the type does not implement Unpin
    PhantomPinned,
);

impl<L: ArraySize> ArrayKey<L> {
    /// The array length in bytes
    pub const SIZE: usize = L::USIZE;

    /// Create a new buffer from a random data source
    #[inline]
    pub fn generate(mut rng: impl KeyMaterial) -> Self {
        Self::new_with(|buf| rng.read_okm(buf))
    }

    /// Create a new buffer using an initializer for the data
    pub fn new_with(f: impl FnOnce(&mut [u8])) -> Self {
        let mut slf = Self::default();
        f(slf.0.as_mut());
        slf
    }

    /// Create a new buffer using a fallible initializer for the data
    pub fn try_new_with<E>(f: impl FnOnce(&mut [u8]) -> Result<(), E>) -> Result<Self, E> {
        let mut slf = Self::default();
        f(slf.0.as_mut())?;
        Ok(slf)
    }

    /// Temporarily allocate and use a key
    pub fn temp<R>(f: impl FnOnce(&mut Array<u8, L>) -> R) -> R {
        let mut slf = Self::default();
        f(&mut slf.0)
    }

    /// Convert this array to a non-zeroing Array instance
    #[inline]
    pub fn extract(self) -> Array<u8, L> {
        self.0.clone()
    }

    /// Create a new array instance from a slice of bytes.
    /// Like <&Array>::from_slice, panics if the length of the slice
    /// is incorrect.
    #[inline]
    pub fn from_slice(data: &[u8]) -> Self {
        Self::from(<&Array<u8, L>>::try_from(data).expect("Invalid array length"))
    }

    /// Get the length of the array
    #[inline]
    pub fn len() -> usize {
        Self::SIZE
    }

    /// Create a new array of random bytes
    #[cfg(feature = "getrandom")]
    #[inline]
    pub fn random() -> Self {
        Self::generate(crate::random::default_rng())
    }

    /// Get a hex formatter for the key data
    pub fn as_hex(&self) -> HexRepr<&[u8]> {
        HexRepr(self.0.as_ref())
    }
}

impl<L: ArraySize> AsRef<Array<u8, L>> for ArrayKey<L> {
    #[inline(always)]
    fn as_ref(&self) -> &Array<u8, L> {
        &self.0
    }
}

impl<L: ArraySize> Deref for ArrayKey<L> {
    type Target = [u8];

    #[inline(always)]
    fn deref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<L: ArraySize> Default for ArrayKey<L> {
    #[inline(always)]
    fn default() -> Self {
        Self(Array::default(), PhantomPinned)
    }
}

impl<L: ArraySize> From<&Array<u8, L>> for ArrayKey<L> {
    #[inline(always)]
    fn from(key: &Array<u8, L>) -> Self {
        Self(key.clone(), PhantomPinned)
    }
}

impl<L: ArraySize> From<Array<u8, L>> for ArrayKey<L> {
    #[inline(always)]
    fn from(key: Array<u8, L>) -> Self {
        Self(key, PhantomPinned)
    }
}

impl<'a, L: ArraySize, const N: usize> TryFrom<&'a ArrayKey<L>> for &'a [u8; N] {
    type Error = TryFromSliceError;

    #[inline(always)]
    fn try_from(key: &ArrayKey<L>) -> Result<&[u8; N], TryFromSliceError> {
        key.0.as_slice().try_into()
    }
}

impl<L: ArraySize> Debug for ArrayKey<L> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if cfg!(test) {
            f.debug_tuple("ArrayKey").field(&self.0).finish()
        } else {
            f.debug_tuple("ArrayKey").field(&"<secret>").finish()
        }
    }
}

impl<L: ArraySize> ConstantTimeEq for ArrayKey<L> {
    fn ct_eq(&self, other: &Self) -> Choice {
        ConstantTimeEq::ct_eq(self.0.as_slice(), other.0.as_slice())
    }
}

impl<L: ArraySize> PartialEq for ArrayKey<L> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl<L: ArraySize> Eq for ArrayKey<L> {}

impl<L: ArraySize> hash::Hash for ArrayKey<L> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<L: ArraySize> Serialize for ArrayKey<L> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

impl<'de, L: ArraySize> Deserialize<'de> for ArrayKey<L> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(KeyVisitor { _pd: PhantomData })
    }
}

impl<L: ArraySize> Zeroize for ArrayKey<L> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<L: ArraySize> Drop for ArrayKey<L> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

struct KeyVisitor<L: ArraySize> {
    _pd: PhantomData<L>,
}

impl<L: ArraySize> de::Visitor<'_> for KeyVisitor<L> {
    type Value = ArrayKey<L>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArrayKey")
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() != L::USIZE {
            return Err(E::invalid_length(value.len(), &self));
        }
        Ok(ArrayKey::from_slice(value))
    }
}

impl<L: ArraySize> FromKeyDerivation for ArrayKey<L> {
    fn from_key_derivation<D: KeyDerivation>(mut derive: D) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Self::try_new_with(|buf| derive.derive_key_bytes(buf))
    }
}
