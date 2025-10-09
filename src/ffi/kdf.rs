use crate::ffi::{error::ErrorCode, secret::SecretBuffer};
use askar_crypto::kdf::{
    argon2::{Argon2, PARAMS_INTERACTIVE, PARAMS_MODERATE},
    KeyDerivation,
};
use ffi_support::ByteBuffer;

/// ## Derive password using Argon2
///
/// If the first provided argument is 1, it will use `PARAMS_INTERACTTIVE` and otherwise it will
/// fallback to `PARAMS_MODERATE`.
///
#[no_mangle]
pub extern "C" fn askar_argon2_derive_password(
    parameters: i8,
    password: ByteBuffer,
    salt: ByteBuffer,
    out: *mut SecretBuffer,
) -> ErrorCode {
    catch_err! {
        let params = match parameters {
            1 => PARAMS_INTERACTIVE,
            _ => PARAMS_MODERATE,
        };

        let mut argon2 = Argon2::new(password.as_slice(), salt.as_slice(), params)?;

        let mut key_out: Vec<u8> = vec![];

        argon2.derive_key_bytes(key_out.as_mut_slice())?;

        unsafe { *out = SecretBuffer::from_secret(key_out) };

        Ok(ErrorCode::Success)
    }
}
