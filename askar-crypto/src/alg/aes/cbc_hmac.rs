//! AES-CBC-HMAC

use core::marker::PhantomData;

use aes_core::{Aes128, Aes256};
use cbc::{Decryptor as CbcDec, Encryptor as CbcEnc};
use cipher::{
    block_padding::Pkcs7, common::BlockSizeUser, BlockCipherDecrypt, BlockCipherEncrypt,
    BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit,
};
use digest::Digest;
use hmac::{Mac, SimpleHmac};
use subtle::ConstantTimeEq;

use super::{AesKey, AesType, NonceSize, TagSize};
use crate::{
    alg::AesTypes,
    array::{
        typenum::{consts, Unsigned},
        Array, ArraySize,
    },
    buffer::ResizeBuffer,
    encrypt::{KeyAeadInPlace, KeyAeadMeta, KeyAeadParams},
    error::Error,
};

/// 128 bit AES-CBC with SHA-256 HMAC
pub type A128CbcHs256 = AesCbcHmac<Aes128, sha2::Sha256>;

impl AesType for A128CbcHs256 {
    type KeySize = consts::U32;
    const ALG_TYPE: AesTypes = AesTypes::A128CbcHs256;
    const JWK_ALG: &'static str = "A128CBC-HS256";
}

/// 256 bit AES-CBC with SHA-512 HMAC
pub type A256CbcHs512 = AesCbcHmac<Aes256, sha2::Sha512>;

impl AesType for A256CbcHs512 {
    type KeySize = consts::U64;
    const ALG_TYPE: AesTypes = AesTypes::A256CbcHs512;
    const JWK_ALG: &'static str = "A256CBC-HS512";
}

/// AES-CBC-HMAC implementation
#[derive(Debug)]
pub struct AesCbcHmac<C, D>(PhantomData<(C, D)>);

impl<C, D> AesCbcHmac<C, D>
where
    C: BlockSizeUser,
{
    #[inline]
    fn padding_length(len: usize) -> usize {
        C::BlockSize::USIZE - (len % C::BlockSize::USIZE)
    }
}

impl<C, D> KeyAeadMeta for AesKey<AesCbcHmac<C, D>>
where
    AesCbcHmac<C, D>: AesType,
    C: BlockSizeUser + KeyInit,
{
    type NonceSize = C::BlockSize;
    type TagSize = C::KeySize;
}

impl<C, D> KeyAeadInPlace for AesKey<AesCbcHmac<C, D>>
where
    AesCbcHmac<C, D>: AesType,
    C: BlockSizeUser + KeyInit + BlockCipherEncrypt + BlockCipherDecrypt,
    D: Digest + BlockSizeUser,
    C::KeySize: core::ops::Shl<consts::B1>,
    <C::KeySize as core::ops::Shl<consts::B1>>::Output: ArraySize,
{
    fn encrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<usize, Error> {
        if nonce.len() != NonceSize::<Self>::USIZE {
            return Err(err_msg!(InvalidNonce));
        }
        // this should be optimized away except when the error is thrown
        if TagSize::<Self>::USIZE > D::OutputSize::USIZE {
            return Err(err_msg!(
                Encryption,
                "AES-CBC-HMAC tag size exceeds maximum supported"
            ));
        }
        if aad.len() as u64 > u64::MAX / 8 {
            return Err(err_msg!(
                Encryption,
                "AES-CBC-HMAC AAD size exceeds maximum supported"
            ));
        }

        let msg_len = buffer.as_ref().len();
        let pad_len = AesCbcHmac::<C, D>::padding_length(msg_len);
        buffer.buffer_extend(pad_len + TagSize::<Self>::USIZE)?;
        let enc_key = Array::try_from(&self.0[C::KeySize::USIZE..]).expect("Invalid key length");
        <CbcEnc<C> as KeyIvInit>::new(
            &enc_key,
            nonce.try_into().map_err(|_| err_msg!(InvalidNonce))?,
        )
        .encrypt_padded::<Pkcs7>(buffer.as_mut(), msg_len)
        .map_err(|_| err_msg!(Encryption, "AES-CBC encryption error"))?;
        let ctext_end = msg_len + pad_len;

        let mut hmac = <SimpleHmac<D> as KeyInit>::new_from_slice(&self.0[..C::KeySize::USIZE])
            .expect("Incompatible HMAC key length");
        hmac.update(aad);
        hmac.update(nonce.as_ref());
        hmac.update(&buffer.as_ref()[..ctext_end]);
        hmac.update(&((aad.len() as u64) * 8).to_be_bytes());
        let mac = hmac.finalize().into_bytes();
        buffer.as_mut()[ctext_end..(ctext_end + TagSize::<Self>::USIZE)]
            .copy_from_slice(&mac[..TagSize::<Self>::USIZE]);

        Ok(ctext_end)
    }

    fn decrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error> {
        if nonce.len() != NonceSize::<Self>::USIZE {
            return Err(err_msg!(InvalidNonce));
        }
        if aad.len() as u64 > u64::MAX / 8 {
            return Err(err_msg!(
                Encryption,
                "AES-CBC-HMAC AAD size exceeds maximum supported"
            ));
        }
        let buf_len = buffer.as_ref().len();
        if buf_len < TagSize::<Self>::USIZE {
            return Err(err_msg!(Encryption, "Invalid size for encrypted data"));
        }
        let ctext_end = buf_len - TagSize::<Self>::USIZE;
        let tag = <&Array<u8, TagSize<Self>>>::try_from(&buffer.as_ref()[ctext_end..])
            .expect("Invalid tag length");

        let mut hmac = <SimpleHmac<D> as KeyInit>::new_from_slice(&self.0[..C::KeySize::USIZE])
            .expect("Incompatible HMAC key length");
        hmac.update(aad);
        hmac.update(nonce.as_ref());
        hmac.update(&buffer.as_ref()[..ctext_end]);
        hmac.update(&((aad.len() as u64) * 8).to_be_bytes());
        let mac = hmac.finalize().into_bytes();
        let tag_match = tag.as_slice().ct_eq(&mac[..TagSize::<Self>::USIZE]);

        let enc_key = Array::try_from(&self.0[C::KeySize::USIZE..]).expect("Invalid key length");
        let dec_len = <CbcDec<C> as KeyIvInit>::new(
            &enc_key,
            nonce.try_into().map_err(|_| err_msg!(InvalidNonce))?,
        )
        .decrypt_padded::<Pkcs7>(&mut buffer.as_mut()[..ctext_end])
        .map_err(|_| err_msg!(Encryption, "AES-CBC decryption error"))?
        .len();
        buffer.buffer_resize(dec_len)?;

        if tag_match.unwrap_u8() != 1 {
            Err(err_msg!(Encryption, "AEAD decryption error"))
        } else {
            Ok(())
        }
    }

    fn aead_params(&self) -> KeyAeadParams {
        KeyAeadParams {
            nonce_length: NonceSize::<Self>::USIZE,
            tag_length: TagSize::<Self>::USIZE,
        }
    }

    fn aead_padding(&self, msg_len: usize) -> usize {
        AesCbcHmac::<C, D>::padding_length(msg_len)
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use std::string::ToString;

    use super::*;
    use crate::buffer::SecretBytes;
    use crate::repr::KeySecretBytes;

    #[test]
    fn encrypt_expected_cbc_128_hmac_256() {
        let key_data = &hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let input = b"A cipher system must not be required to be secret, and it must be able to fall into the hands of the enemy without inconvenience";
        let nonce = &hex!("1af38c2dc2b96ffdd86694092341bc04");
        let aad = b"The second principle of Auguste Kerckhoffs";
        let key = AesKey::<A128CbcHs256>::from_secret_bytes(key_data).unwrap();
        let mut buffer = SecretBytes::from_slice(input);
        key.encrypt_in_place(&mut buffer, &nonce[..], &aad[..])
            .unwrap();

        assert_eq!(
            buffer.as_hex().to_string(),
            "c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9\
            a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c7032336\
            09d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b\
            384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade5\
            4b8851ffb598f7f80074b9473c82e2db652c3fa36b0a7c5b3219fab3a30bc1c4"
        );
        key.decrypt_in_place(&mut buffer, &nonce[..], &aad[..])
            .unwrap();
        assert_eq!(buffer, &input[..]);
    }

    #[test]
    fn encrypt_expected_cbc_256_hmac_512() {
        let key_data = &hex!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
            202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        );
        let input = b"A cipher system must not be required to be secret, and it must be able to fall into the hands of the enemy without inconvenience";
        let nonce = &hex!("1af38c2dc2b96ffdd86694092341bc04");
        let aad = b"The second principle of Auguste Kerckhoffs";
        let key = AesKey::<A256CbcHs512>::from_secret_bytes(key_data).unwrap();
        let mut buffer = SecretBytes::from_slice(input);
        key.encrypt_in_place(&mut buffer, &nonce[..], &aad[..])
            .unwrap();

        assert_eq!(
            buffer.as_hex().to_string(),
            "4affaaadb78c31c5da4b1b590d10ffbd3dd8d5d302423526912da037ecbcc7bd\
            822c301dd67c373bccb584ad3e9279c2e6d12a1374b77f077553df829410446b\
            36ebd97066296ae6427ea75c2e0846a11a09ccf5370dc80bfecbad28c73f09b3\
            a3b75e662a2594410ae496b2e2e6609e31e6e02cc837f053d21f37ff4f51950b\
            be2638d09dd7a4930930806d0703b1f64dd3b4c088a7f45c216839645b2012bf\
            2e6269a8c56a816dbc1b267761955bc5"
        );
        key.decrypt_in_place(&mut buffer, &nonce[..], &aad[..])
            .unwrap();
        assert_eq!(buffer, &input[..]);
    }

    #[test]
    fn encrypt_expected_ecdh_1pu_cbc_hmac() {
        let key_data = &hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0
            dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0"
        );
        let nonce = &hex!("000102030405060708090a0b0c0d0e0f");
        let protected = "{\"alg\":\"ECDH-1PU+A128KW\",\"enc\":\"A256CBC-HS512\",\
            \"apu\":\"QWxpY2U\",\"apv\":\"Qm9iIGFuZCBDaGFybGll\",\"epk\":{\
                \"kty\":\"OKP\",\"crv\":\"X25519\",\
                \"x\":\"k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc\"}}";
        let aad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(protected);
        let input = b"Three is a magic number.";
        let key = AesKey::<A256CbcHs512>::from_secret_bytes(key_data).unwrap();
        let mut buffer = SecretBytes::from_slice(input);
        let ct_len = key
            .encrypt_in_place(&mut buffer, &nonce[..], aad.as_bytes())
            .unwrap();
        let ctext =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buffer.as_ref()[..ct_len]);
        let tag =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buffer.as_ref()[ct_len..]);
        assert_eq!(ctext, "Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw");
        assert_eq!(tag, "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ");
        key.decrypt_in_place(&mut buffer, &nonce[..], aad.as_bytes())
            .unwrap();
        assert_eq!(buffer, &input[..]);
    }
}
