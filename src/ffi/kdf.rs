use crate::ffi::{error::ErrorCode, secret::SecretBuffer};
use askar_crypto::kdf::{
    argon2::{
        Algorithm as Argon2Algorithm, Argon2, Params as Argon2Params, Version as Argon2Version,
        PARAMS_INTERACTIVE, PARAMS_MODERATE,
    },
    KeyDerivation,
};
use ffi_support::ByteBuffer;

#[repr(C)]
pub struct Argon2Config {
    /// The algorithm is determined by a numeric code.
    /// 0: argon2d
    /// 1: argon2i
    /// 2: argon2id
    algorithm: i32,
    /// The version is determined by a numeric code.
    /// 16: version 0x10
    /// 19: version 0x13
    version: i32,
    /// The level of parallelism.
    parallelism: i32,
    /// The memory cost, measured in kibibytes.
    mem_cost: i32,
    /// The time cost, measured in iterations.
    time_cost: i32,
}

/// ## Derive password using Argon2
///
/// The `parameters` argument determines the Argon2 derivation parameters:
/// `-1`: apply the custom parameters contained in `config`, otherwise `config` must be a null pointer.
/// `0`: use the `PARAMS_MODERATE` parameters
/// `1`: use the `PARAMS_INTERACTIVE` parameters
///
#[no_mangle]
pub extern "C" fn askar_argon2_derive_password(
    parameters: i8,
    password: ByteBuffer,
    salt: ByteBuffer,
    config: *const Argon2Config,
    out: *mut SecretBuffer,
) -> ErrorCode {
    catch_err! {
        let params = if parameters == -1 {
            if let Some(cfg) = unsafe { config.as_ref() } {
                let alg = match cfg.algorithm {
                    0 => Argon2Algorithm::Argon2d,
                    1 => Argon2Algorithm::Argon2i,
                    2 => Argon2Algorithm::Argon2id,
                    _ => return Err(err_msg!("Invalid value for algorithm"))
                };
                let version = match cfg.version {
                    16 => Argon2Version::V0x10,
                    19 => Argon2Version::V0x13,
                    _ => return Err(err_msg!("Invalid value for version"))
                };
                let parallelism = if cfg.parallelism > 0 {
                    cfg.parallelism as u32
                } else {
                    return Err(err_msg!("Invalid value for parallelism"))
                };
                let mem_cost = if cfg.mem_cost > 0 {
                    cfg.mem_cost as u32
                } else {
                    return Err(err_msg!("Invalid value for mem_cost"))
                };
                let time_cost = if cfg.time_cost > 0 {
                    cfg.time_cost as u32
                } else {
                    return Err(err_msg!("Invalid value for time_cost"))
                };
                Argon2Params {
                    alg,
                    version,
                    parallelism,
                    mem_cost,
                    time_cost,
                }
            } else {
                return Err(err_msg!("Expected pointer to config"))
            }
        } else {
            if !config.is_null() {
                return Err(err_msg!("Unexpected custom configuration"))
            }
            match parameters {
                0 => PARAMS_MODERATE,
                1 => PARAMS_INTERACTIVE,
                _ => return Err(err_msg!("Invalid value for parameters"))
            }
        };

        let mut argon2 = Argon2::new(password.as_slice(), salt.as_slice(), params)?;

        let mut key_out = [0u8; 32];

        argon2.derive_key_bytes(key_out.as_mut_slice())?;

        unsafe { *out = SecretBuffer::from_secret(key_out.as_slice()) };

        Ok(ErrorCode::Success)
    }
}
