//! Argon2 key derivation from a password

pub use argon2::{Algorithm, Version};

use super::KeyDerivation;
use crate::{
    error::Error,
    generic_array::typenum::{Unsigned, U16},
};

/// The size of the password salt
pub type SaltSize = U16;

/// The length of the password salt
pub const SALT_LENGTH: usize = SaltSize::USIZE;

/// Standard parameters for 'interactive' level
pub const PARAMS_INTERACTIVE: Params = Params {
    alg: Algorithm::Argon2i,
    version: Version::V0x13,
    mem_cost: 32768,
    time_cost: 4,
    parallelism: 1,
};
/// Standard parameters for 'moderate' level
pub const PARAMS_MODERATE: Params = Params {
    alg: Algorithm::Argon2i,
    version: Version::V0x13,
    mem_cost: 131072,
    time_cost: 6,
    parallelism: 1,
};

/// Parameters to the argon2 key derivation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// The Argon2 algorithm to use
    pub alg: Algorithm,
    /// The Argon2 version to use
    pub version: Version,
    /// The level of parallelism
    pub parallelism: u32,
    /// The memory cost of the derivation, in kibibytes
    pub mem_cost: u32,
    /// The time cost of the derivation, in iterations
    pub time_cost: u32,
}

/// Struct wrapping the KDF functionality
#[derive(Debug)]
pub struct Argon2<'a> {
    password: &'a [u8],
    salt: &'a [u8],
    params: Params,
}

impl<'a> Argon2<'a> {
    /// Create a new Argon2 key derivation instance
    pub fn new(password: &'a [u8], salt: &'a [u8], params: Params) -> Result<Self, Error> {
        if salt.len() < SALT_LENGTH {
            return Err(err_msg!(Usage, "Invalid salt for argon2 hash"));
        }
        Ok(Self {
            password,
            salt,
            params,
        })
    }
}

impl KeyDerivation for Argon2<'_> {
    fn derive_key_bytes(&mut self, key_output: &mut [u8]) -> Result<(), Error> {
        if key_output.len() > u32::MAX as usize {
            return Err(err_msg!(Usage, "Output length exceeds max for argon2 hash"));
        }
        let mut pbuild = argon2::ParamsBuilder::new();
        pbuild
            .p_cost(self.params.parallelism)
            .m_cost(self.params.mem_cost)
            .t_cost(self.params.time_cost);
        argon2::Argon2::new(
            self.params.alg,
            self.params.version,
            pbuild.build().unwrap(),
        )
        .hash_password_into(self.password, self.salt, key_output)
        .map_err(|_| err_msg!(Unexpected, "Error deriving key"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected() {
        let pass = b"my password";
        let salt = b"long enough salt";
        let mut output = [0u8; 32];
        Argon2::new(pass, salt, PARAMS_INTERACTIVE)
            .unwrap()
            .derive_key_bytes(&mut output)
            .unwrap();
        assert_eq!(
            output,
            hex!("9ef87bcf828c46c0136a0d1d9e391d713f75b327c6dc190455bd36c1bae33259")
        );
    }
}
