use askar_crypto::kdf::KeyDerivation;

use crate::{
    crypto::{
        buffer::ArrayKey,
        kdf::argon2::{Argon2, Params, PARAMS_INTERACTIVE, PARAMS_MODERATE},
        repr::{KeyMeta, KeySecretBytes},
    },
    error::Error,
    protect::store_key::{StoreKey, StoreKeyType},
};

pub use crate::crypto::kdf::argon2::SaltSize;

pub const LEVEL_INTERACTIVE: &str = "13:int";
pub const LEVEL_MODERATE: &str = "13:mod";

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Level {
    Interactive,
    Moderate,
}

impl Default for Level {
    fn default() -> Self {
        Self::Moderate
    }
}

impl Level {
    pub fn from_str(level: &str) -> Option<Self> {
        match level {
            "int" | LEVEL_INTERACTIVE => Some(Self::Interactive),
            "mod" | LEVEL_MODERATE => Some(Self::Moderate),
            "" => Some(Self::default()),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Interactive => LEVEL_INTERACTIVE,
            Self::Moderate => LEVEL_MODERATE,
        }
    }

    pub fn generate_salt(&self) -> ArrayKey<SaltSize> {
        ArrayKey::random()
    }

    fn params(&self) -> &Params {
        match self {
            Self::Interactive => &PARAMS_INTERACTIVE,
            Self::Moderate => &PARAMS_MODERATE,
        }
    }

    pub fn derive_key(&self, password: &[u8], salt: &[u8]) -> Result<StoreKey, Error> {
        ArrayKey::<<StoreKeyType as KeyMeta>::KeySize>::temp(|key| {
            Argon2::new(password, salt, *self.params())?.derive_key_bytes(key)?;
            Ok(StoreKey::from(StoreKeyType::from_secret_bytes(&*key)?))
        })
    }
}
