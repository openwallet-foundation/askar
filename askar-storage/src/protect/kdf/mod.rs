//! Key derivations

use super::store_key::{StoreKey, PREFIX_KDF};
use crate::{
    crypto::{array::ArraySize, buffer::ArrayKey},
    error::Error,
    options::Options,
};

mod argon2;
pub use self::argon2::Level as Argon2Level;
use self::argon2::SaltSize as Argon2Salt;

pub const METHOD_ARGON2I: &str = "argon2i";

/// Supported KDF methods for generating or referencing a store key
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum KdfMethod {
    /// Argon2i derivation method
    Argon2i(Argon2Level),
}

impl KdfMethod {
    pub(crate) fn decode(method: &str) -> Result<(Self, String), Error> {
        let mut method_and_detail = method.splitn(3, ':');
        let prefix = method_and_detail.next();
        if prefix == Some(PREFIX_KDF) {
            let method = method_and_detail.next().unwrap_or_default();
            let mut level_and_detail = method_and_detail.next().unwrap_or_default().splitn(2, '?');
            let level = level_and_detail.next().unwrap_or_default();
            let detail = level_and_detail.next().unwrap_or_default();
            if method == METHOD_ARGON2I {
                if let Some(level) = Argon2Level::from_str(level) {
                    return Ok((
                        Self::Argon2i(level),
                        if detail.is_empty() {
                            "".to_owned()
                        } else {
                            format!("?{}", detail)
                        },
                    ));
                }
            }
        }
        Err(err_msg!(Unsupported, "Invalid key derivation method"))
    }

    pub(crate) fn encode(&self, detail: Option<&str>) -> String {
        match self {
            Self::Argon2i(level) => format!(
                "{}:{}:{}{}",
                PREFIX_KDF,
                METHOD_ARGON2I,
                level.as_str(),
                detail.unwrap_or_default()
            ),
        }
    }

    pub(crate) fn derive_new_key(&self, password: &str) -> Result<(StoreKey, String), Error> {
        match self {
            Self::Argon2i(level) => {
                let salt = level.generate_salt();
                let key = level.derive_key(password.as_bytes(), salt.as_ref())?;
                let detail = format!("?salt={}", salt.as_hex());
                Ok((key, detail))
            }
        }
    }

    pub(crate) fn derive_key(&self, password: &str, detail: &str) -> Result<StoreKey, Error> {
        match self {
            Self::Argon2i(level) => {
                let salt = parse_salt::<Argon2Salt>(detail)?;
                let key = level.derive_key(password.as_bytes(), salt.as_ref())?;
                Ok(key)
            }
        }
    }
}

fn parse_salt<L: ArraySize>(detail: &str) -> Result<ArrayKey<L>, Error> {
    let opts = Options::parse_uri(detail)?;
    if let Some(salt) = opts.query.get("salt") {
        ArrayKey::<L>::try_new_with(|arr| {
            hex::decode_to_slice(salt, arr).map_err(|_| err_msg!(Input, "Invalid salt"))
        })
    } else {
        Err(err_msg!(Input, "Missing salt"))
    }
}
