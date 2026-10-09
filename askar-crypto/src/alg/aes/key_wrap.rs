//! AES key wrap

use core::marker::PhantomData;

use aes_core::{
    cipher::{common::BlockSizeUser, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, KeySizeUser},
    Aes128, Aes256,
};
use subtle::ConstantTimeEq;

use super::{AesKey, AesType, NonceSize, TagSize};
use crate::{
    alg::AesTypes,
    array::{
        typenum::{consts, Unsigned},
        Array,
    },
    buffer::ResizeBuffer,
    encrypt::{KeyAeadInPlace, KeyAeadMeta, KeyAeadParams},
    error::Error,
};

const AES_KW_DEFAULT_IV: [u8; 8] = [166, 166, 166, 166, 166, 166, 166, 166];

/// 128 bit AES Key Wrap
pub type A128Kw = AesKeyWrap<Aes128>;

impl AesType for A128Kw {
    type KeySize = <Aes128 as KeySizeUser>::KeySize;
    const ALG_TYPE: AesTypes = AesTypes::A128Kw;
    const JWK_ALG: &'static str = "A128KW";
}

/// 256 bit AES Key Wrap
pub type A256Kw = AesKeyWrap<Aes256>;

impl AesType for A256Kw {
    type KeySize = <Aes256 as KeySizeUser>::KeySize;
    const ALG_TYPE: AesTypes = AesTypes::A256Kw;
    const JWK_ALG: &'static str = "A256KW";
}

/// AES Key Wrap implementation
#[derive(Debug)]
pub struct AesKeyWrap<C>(PhantomData<C>);

impl<C> KeyAeadMeta for AesKey<AesKeyWrap<C>>
where
    AesKeyWrap<C>: AesType,
{
    type NonceSize = consts::U0;
    type TagSize = consts::U8;
}

impl<C> KeyAeadInPlace for AesKey<AesKeyWrap<C>>
where
    AesKeyWrap<C>: AesType,
    C: KeyInit
        + KeySizeUser<KeySize = <AesKeyWrap<C> as AesType>::KeySize>
        + BlockSizeUser<BlockSize = consts::U16>
        + BlockCipherDecrypt
        + BlockCipherEncrypt,
{
    fn encrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<usize, Error> {
        if !nonce.is_empty() {
            return Err(err_msg!(Unsupported, "Custom nonce not supported"));
        }
        if !aad.is_empty() {
            return Err(err_msg!(Unsupported, "AAD not supported"));
        }
        let mut buf_len = buffer.as_ref().len();
        if buf_len % 8 != 0 {
            return Err(err_msg!(
                Unsupported,
                "Data length must be a multiple of 8 bytes"
            ));
        }
        let blocks = buf_len / 8;

        buffer.buffer_insert(0, &[0u8; 8])?;
        buf_len += 8;

        let aes = C::new(self.0.as_ref());
        let mut iv = AES_KW_DEFAULT_IV;
        let mut block = Array::default();
        for j in 0..6 {
            for (i, chunk) in buffer.as_mut()[8..].chunks_exact_mut(8).enumerate() {
                block[0..8].copy_from_slice(iv.as_ref());
                block[8..16].copy_from_slice(chunk);
                aes.encrypt_block(&mut block);
                let t = (((blocks * j) + i + 1) as u64).to_be_bytes();
                iv.copy_from_slice(&block[0..8]);
                for (a, t) in iv.as_mut().iter_mut().zip(&t[..]) {
                    *a ^= t;
                }
                chunk.copy_from_slice(&block[8..16]);
            }
        }
        buffer.as_mut()[0..8].copy_from_slice(&iv[..]);
        Ok(buf_len)
    }

    fn decrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error> {
        if !nonce.is_empty() {
            return Err(err_msg!(Unsupported, "Custom nonce not supported"));
        }
        if !aad.is_empty() {
            return Err(err_msg!(Unsupported, "AAD not supported"));
        }
        if buffer.as_ref().len() % 8 != 0 {
            return Err(err_msg!(
                Encryption,
                "Data length must be a multiple of 8 bytes"
            ));
        }
        let mut blocks = buffer.as_ref().len() / 8;
        if blocks < 1 {
            return Err(err_msg!(Encryption));
        }
        blocks -= 1;

        let aes = C::new(self.0.as_ref());
        let mut iv = *TryInto::<&[u8; 8]>::try_into(&buffer.as_ref()[0..8]).unwrap();
        buffer.buffer_remove(0..8)?;

        let mut block = Array::default();
        for j in (0..6).rev() {
            for (i, chunk) in buffer.as_mut().chunks_exact_mut(8).enumerate().rev() {
                block[0..8].copy_from_slice(iv.as_ref());
                let t = (((blocks * j) + i + 1) as u64).to_be_bytes();
                for (a, t) in block[0..8].iter_mut().zip(&t[..]) {
                    *a ^= t;
                }
                block[8..16].copy_from_slice(chunk);
                aes.decrypt_block(&mut block);
                iv.copy_from_slice(&block[0..8]);
                chunk.copy_from_slice(&block[8..16]);
            }
        }

        if iv.ct_eq(&AES_KW_DEFAULT_IV).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(err_msg!(Encryption))
        }
    }

    fn aead_params(&self) -> KeyAeadParams {
        KeyAeadParams {
            nonce_length: NonceSize::<Self>::USIZE,
            tag_length: TagSize::<Self>::USIZE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::SecretBytes;
    use crate::repr::KeySecretBytes;
    use std::string::ToString;

    #[test]
    // from RFC 3394 test vectors
    fn key_wrap_128_expected() {
        let key =
            AesKey::<A128Kw>::from_secret_bytes(&hex!("000102030405060708090a0b0c0d0e0f")).unwrap();
        let input = &hex!("00112233445566778899aabbccddeeff");
        let mut buffer = SecretBytes::from_slice(input);
        key.encrypt_in_place(&mut buffer, &[], &[]).unwrap();
        assert_eq!(
            buffer.as_hex().to_string(),
            "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"
        );
        key.decrypt_in_place(&mut buffer, &[], &[]).unwrap();
        assert_eq!(buffer, &input[..]);
    }

    #[test]
    // from RFC 3394 test vectors
    fn key_wrap_256_expected() {
        let key = AesKey::<A256Kw>::from_secret_bytes(&hex!(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
        ))
        .unwrap();
        let input = &hex!("00112233445566778899aabbccddeeff");
        let mut buffer = SecretBytes::from_slice(input);
        key.encrypt_in_place(&mut buffer, &[], &[]).unwrap();
        assert_eq!(
            buffer.as_hex().to_string(),
            "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7"
        );
        key.decrypt_in_place(&mut buffer, &[], &[]).unwrap();
        assert_eq!(buffer, &input[..]);
    }
}
