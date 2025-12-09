use super::{
    handle::ArcHandle,
    result_list::{FfiStringList, StringListHandle},
    secret::{EncryptedBuffer, SecretBuffer},
    ErrorCode,
};
use crate::kms::{
    crypto_box, crypto_box_open, crypto_box_random_nonce, crypto_box_seal, crypto_box_seal_open,
    derive_key_ecdh_1pu, derive_key_ecdh_es, KeyAlg, KeyBackend, LocalKey,
};
use ffi_support::{rust_string_to_c, ByteBuffer, FfiStr};
use std::{os::raw::c_char, str::FromStr};

pub type LocalKeyHandle = ArcHandle<LocalKey>;

#[repr(C)]
pub struct AeadParams {
    nonce_length: i32,
    tag_length: i32,
}

#[no_mangle]
pub extern "C" fn askar_key_generate(
    alg: FfiStr<'_>,
    key_backend: FfiStr<'_>,
    ephemeral: i8,
    out: *mut LocalKeyHandle,
) -> ErrorCode {
    catch_err! {
        let alg = alg.as_opt_str().unwrap_or_default();
        let key_backend = key_backend.as_opt_str().unwrap_or_default();
        let backend = KeyBackend::from_str(key_backend).unwrap_or_default();
        trace!("Generate key: {} for {} backend", alg, backend);
        check_useful_c_ptr!(out);

        let alg = KeyAlg::from_str(alg)?;

        let key = match backend {
            KeyBackend::Software => LocalKey::generate_with_rng(alg, ephemeral != 0),
            KeyBackend::SecureElement => LocalKey::generate_for_hardware(alg, ephemeral != 0)
        }?;

        unsafe { *out = LocalKeyHandle::create(key) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_from_seed(
    alg: FfiStr<'_>,
    seed: ByteBuffer,
    method: FfiStr<'_>,
    out: *mut LocalKeyHandle,
) -> ErrorCode {
    catch_err! {
        let alg = alg.as_opt_str().unwrap_or_default();
        trace!("Create key from seed: {}", alg);
        check_useful_c_ptr!(out);
        let alg = KeyAlg::from_str(alg)?;
        let key = LocalKey::from_seed(alg, seed.as_slice(), method.as_opt_str())?;
        unsafe { *out = LocalKeyHandle::create(key) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_from_jwk(jwk: ByteBuffer, out: *mut LocalKeyHandle) -> ErrorCode {
    catch_err! {
        trace!("Load key from JWK");
        check_useful_c_ptr!(out);
        let key = LocalKey::from_jwk_slice(jwk.as_slice())?;
        unsafe { *out = LocalKeyHandle::create(key) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_from_public_bytes(
    alg: FfiStr<'_>,
    public: ByteBuffer,
    out: *mut LocalKeyHandle,
) -> ErrorCode {
    catch_err! {
        let alg = alg.as_opt_str().unwrap_or_default();
        trace!("Load key from public: {}", alg);
        check_useful_c_ptr!(out);
        let alg = KeyAlg::from_str(alg)?;
        let key = LocalKey::from_public_bytes(alg, public.as_slice())?;
        unsafe { *out = LocalKeyHandle::create(key) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_get_public_bytes(
    handle: LocalKeyHandle,
    out: *mut SecretBuffer,
) -> ErrorCode {
    catch_err! {
        trace!("Get key public bytes: {}", handle);
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        let public = key.to_public_bytes()?;
        unsafe { *out = SecretBuffer::from_secret(public) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_from_secret_bytes(
    alg: FfiStr<'_>,
    secret: ByteBuffer,
    out: *mut LocalKeyHandle,
) -> ErrorCode {
    catch_err! {
        let alg = alg.as_opt_str().unwrap_or_default();
        trace!("Load key from secret: {}", alg);
        check_useful_c_ptr!(out);
        let alg = KeyAlg::from_str(alg)?;
        let key = LocalKey::from_secret_bytes(alg, secret.as_slice())?;
        unsafe { *out = LocalKeyHandle::create(key) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_get_secret_bytes(
    handle: LocalKeyHandle,
    out: *mut SecretBuffer,
) -> ErrorCode {
    catch_err! {
        trace!("Get key secret bytes: {}", handle);
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        let public = key.to_secret_bytes()?;
        unsafe { *out = SecretBuffer::from_secret(public) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_convert(
    handle: LocalKeyHandle,
    alg: FfiStr<'_>,
    out: *mut LocalKeyHandle,
) -> ErrorCode {
    catch_err! {
        let alg = alg.as_opt_str().unwrap_or_default();
        trace!("Convert key: {} to {}", handle, alg);
        check_useful_c_ptr!(out);
        let alg = KeyAlg::from_str(alg)?;
        let key = handle.load()?.convert_key(alg)?;
        unsafe { *out = LocalKeyHandle::create(key) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_from_key_exchange(
    alg: FfiStr<'_>,
    sk_handle: LocalKeyHandle,
    pk_handle: LocalKeyHandle,
    out: *mut LocalKeyHandle,
) -> ErrorCode {
    catch_err! {
        let alg = alg.as_opt_str().unwrap_or_default();
        trace!("Key exchange: {}, {}, {}", alg, sk_handle, pk_handle);
        check_useful_c_ptr!(out);
        let alg = KeyAlg::from_str(alg)?;
        let sk = sk_handle.load()?;
        let pk = pk_handle.load()?;
        let key = sk.to_key_exchange(alg, &pk)?;
        unsafe { *out = LocalKeyHandle::create(key) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_free(handle: LocalKeyHandle) {
    handle.remove();
}

#[no_mangle]
pub extern "C" fn askar_key_get_algorithm(
    handle: LocalKeyHandle,
    out: *mut *const c_char,
) -> ErrorCode {
    catch_err! {
        trace!("Get key algorithm: {}", handle);
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        unsafe { *out = rust_string_to_c(key.algorithm().as_str()) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_get_ephemeral(handle: LocalKeyHandle, out: *mut i8) -> ErrorCode {
    catch_err! {
        trace!("Get key ephemeral: {}", handle);
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        unsafe { *out = key.ephemeral as i8 };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_get_jwk_public(
    handle: LocalKeyHandle,
    alg: FfiStr<'_>,
    out: *mut *const c_char,
) -> ErrorCode {
    catch_err! {
        trace!("Get key JWK public: {}", handle);
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        let alg = alg.as_opt_str().map(KeyAlg::from_str).transpose()?;
        let jwk = key.to_jwk_public(alg)?;
        unsafe { *out = rust_string_to_c(jwk) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_get_jwk_secret(
    handle: LocalKeyHandle,
    out: *mut SecretBuffer,
) -> ErrorCode {
    catch_err! {
        trace!("Get key JWK secret: {}", handle);
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        let jwk = key.to_jwk_secret()?;
        unsafe { *out = SecretBuffer::from_secret(jwk) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_get_jwk_thumbprint(
    handle: LocalKeyHandle,
    alg: FfiStr<'_>,
    out: *mut *const c_char,
) -> ErrorCode {
    catch_err! {
        trace!("Get key JWK thumbprint: {}", handle);
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        let alg = alg.as_opt_str().map(KeyAlg::from_str).transpose()?;
        let thumb = key.to_jwk_thumbprint(alg)?;
        unsafe { *out = rust_string_to_c(thumb) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_aead_random_nonce(
    handle: LocalKeyHandle,
    out: *mut SecretBuffer,
) -> ErrorCode {
    catch_err! {
        trace!("AEAD create nonce: {}", handle);
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        let nonce = key.aead_random_nonce()?;
        unsafe { *out = SecretBuffer::from_secret(nonce) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_aead_get_params(
    handle: LocalKeyHandle,
    out: *mut AeadParams,
) -> ErrorCode {
    catch_err! {
        trace!("AEAD get params: {}", handle);
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        let params = key.aead_params()?;
        unsafe { *out = AeadParams {
            nonce_length: params.nonce_length as i32,
            tag_length: params.tag_length as i32
        } };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_aead_get_padding(
    handle: LocalKeyHandle,
    msg_len: i64,
    out: *mut i32,
) -> ErrorCode {
    catch_err! {
        trace!("AEAD get padding: {}", handle);
        check_useful_c_ptr!(out);
        if msg_len < 0 {
            return Err(err_msg!("Invalid message length"));
        }
        let key = handle.load()?;
        let padding = key.aead_padding(msg_len as usize);
        unsafe { *out = padding as i32 };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_aead_encrypt(
    handle: LocalKeyHandle,
    message: ByteBuffer,
    nonce: ByteBuffer,
    aad: ByteBuffer,
    out: *mut EncryptedBuffer,
) -> ErrorCode {
    catch_err! {
        trace!("AEAD encrypt: {}", handle);
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        let enc = key.aead_encrypt(message.as_slice(), nonce.as_slice(), aad.as_slice())?;
        let result = EncryptedBuffer::from_encrypted(enc);
        unsafe { *out = result };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_aead_decrypt(
    handle: LocalKeyHandle,
    ciphertext: ByteBuffer,
    nonce: ByteBuffer,
    tag: ByteBuffer,
    aad: ByteBuffer,
    out: *mut SecretBuffer,
) -> ErrorCode {
    catch_err! {
        trace!("AEAD decrypt: {}", handle);
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        let dec = key.aead_decrypt((ciphertext.as_slice(), tag.as_slice()), nonce.as_slice(), aad.as_slice())?;
        unsafe { *out = SecretBuffer::from_secret(dec) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_sign_message(
    handle: LocalKeyHandle,
    message: ByteBuffer,
    sig_type: FfiStr<'_>,
    out: *mut SecretBuffer,
) -> ErrorCode {
    catch_err! {
        trace!("Sign message: {}", handle);
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        let sig = key.sign_message(message.as_slice(), sig_type.as_opt_str())?;
        unsafe { *out = SecretBuffer::from_secret(sig) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_verify_signature(
    handle: LocalKeyHandle,
    message: ByteBuffer,
    signature: ByteBuffer,
    sig_type: FfiStr<'_>,
    out: *mut i8,
) -> ErrorCode {
    catch_err! {
        trace!("Verify signature: {}", handle);
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        let verify = key.verify_signature(message.as_slice(), signature.as_slice(), sig_type.as_opt_str())?;
        unsafe { *out = verify as i8 };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_wrap_key(
    handle: LocalKeyHandle,
    other: LocalKeyHandle,
    nonce: ByteBuffer,
    out: *mut EncryptedBuffer,
) -> ErrorCode {
    catch_err! {
        trace!("Wrap key: {}", handle);
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        let other = other.load()?;
        let result = key.wrap_key(&other, nonce.as_slice())?;
        unsafe { *out = EncryptedBuffer::from_encrypted(result) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_unwrap_key(
    handle: LocalKeyHandle,
    alg: FfiStr<'_>,
    ciphertext: ByteBuffer,
    nonce: ByteBuffer,
    tag: ByteBuffer,
    out: *mut LocalKeyHandle,
) -> ErrorCode {
    catch_err! {
        let alg = alg.as_opt_str().unwrap_or_default();
        trace!("Unwrap key: {}", handle);
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        let alg = KeyAlg::from_str(alg)?;
        let result = key.unwrap_key(alg, (ciphertext.as_slice(), tag.as_slice()), nonce.as_slice())?;
        unsafe { *out = LocalKeyHandle::create(result) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_crypto_box_random_nonce(out: *mut SecretBuffer) -> ErrorCode {
    catch_err! {
        trace!("crypto box random nonce");
        check_useful_c_ptr!(out);
        let nonce = crypto_box_random_nonce()?;
        unsafe { *out = SecretBuffer::from_secret(&nonce[..]) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_crypto_box(
    recip_key: LocalKeyHandle,
    sender_key: LocalKeyHandle,
    message: ByteBuffer,
    nonce: ByteBuffer,
    out: *mut SecretBuffer,
) -> ErrorCode {
    catch_err! {
        trace!("crypto box: {}, {}", recip_key, sender_key);
        check_useful_c_ptr!(out);
        let recip_key = recip_key.load()?;
        let sender_key = sender_key.load()?;
        let message = crypto_box(
            &recip_key,
            &sender_key,
            message.as_slice(),
            nonce.as_slice()
        )?;
        unsafe { *out = SecretBuffer::from_secret(message) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_crypto_box_open(
    recip_key: LocalKeyHandle,
    sender_key: LocalKeyHandle,
    message: ByteBuffer,
    nonce: ByteBuffer,
    out: *mut SecretBuffer,
) -> ErrorCode {
    catch_err! {
        trace!("crypto box open: {}, {}", recip_key, sender_key);
        check_useful_c_ptr!(out);
        let recip_key = recip_key.load()?;
        let sender_key = sender_key.load()?;
        let message = crypto_box_open(
            &recip_key,
            &sender_key,
            message.as_slice(),
            nonce.as_slice()
        )?;
        unsafe { *out = SecretBuffer::from_secret(message) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_crypto_box_seal(
    handle: LocalKeyHandle,
    message: ByteBuffer,
    out: *mut SecretBuffer,
) -> ErrorCode {
    catch_err! {
        trace!("crypto box seal: {}", handle);
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        let enc = crypto_box_seal(&key, message.as_slice())?;
        unsafe { *out = SecretBuffer::from_secret(enc) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_crypto_box_seal_open(
    handle: LocalKeyHandle,
    ciphertext: ByteBuffer,
    out: *mut SecretBuffer,
) -> ErrorCode {
    catch_err! {
        trace!("crypto box seal open: {}", handle);
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        let enc = crypto_box_seal_open(&key, ciphertext.as_slice())?;
        unsafe { *out = SecretBuffer::from_secret(enc) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_derive_ecdh_es(
    alg: FfiStr<'_>,
    ephem_key: LocalKeyHandle,
    recip_key: LocalKeyHandle,
    alg_id: ByteBuffer,
    apu: ByteBuffer,
    apv: ByteBuffer,
    receive: i8,
    out: *mut LocalKeyHandle,
) -> ErrorCode {
    catch_err! {
        let alg = alg.as_opt_str().unwrap_or_default();
        trace!("ECDH-ES: {}", alg);
        check_useful_c_ptr!(out);
        let alg = KeyAlg::from_str(alg)?;
        let ephem_key = ephem_key.load()?;
        let recip_key = recip_key.load()?;
        let key = derive_key_ecdh_es(
            alg,
            &ephem_key,
            &recip_key,
            alg_id.as_slice(),
            apu.as_slice(),
            apv.as_slice(),
            receive == 1
        )?;
        unsafe { *out = LocalKeyHandle::create(key) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_derive_ecdh_1pu(
    alg: FfiStr<'_>,
    ephem_key: LocalKeyHandle,
    sender_key: LocalKeyHandle,
    recip_key: LocalKeyHandle,
    alg_id: ByteBuffer,
    apu: ByteBuffer,
    apv: ByteBuffer,
    cc_tag: ByteBuffer,
    receive: i8,
    out: *mut LocalKeyHandle,
) -> ErrorCode {
    catch_err! {
        let alg = alg.as_opt_str().unwrap_or_default();
        trace!("ECDH-1PU: {}", alg);
        check_useful_c_ptr!(out);
        let alg = KeyAlg::from_str(alg)?;
        let ephem_key = ephem_key.load()?;
        let sender_key = sender_key.load()?;
        let recip_key = recip_key.load()?;
        let key = derive_key_ecdh_1pu(
            alg,
            &ephem_key,
            &sender_key,
            &recip_key,
            alg_id.as_slice(),
            apu.as_slice(),
            apv.as_slice(),
            cc_tag.as_slice(),
            receive == 1
        )?;
        unsafe { *out = LocalKeyHandle::create(key) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_get_supported_backends(out: *mut StringListHandle) -> ErrorCode {
    catch_err! {
        trace!("Retrieving supported key backends");
        check_useful_c_ptr!(out);

        let mut backends = vec![KeyBackend::Software];

        let backends: Vec<String> = backends
            .iter()
            .map(|b| <KeyBackend as Into<&str>>::into(b.clone()).to_owned())
            .collect();

        let string_list = StringListHandle::create(FfiStringList::from(backends));

        unsafe { *out = string_list };

        Ok(ErrorCode::Success)
    }
}
