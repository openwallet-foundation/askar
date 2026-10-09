//! Compatibility with libsodium's crypto_box construct
//!
//! A crypto box is an X25519 key exchange, followed by HSalsa20 key derivation,
//! followed by the XSalsa20-Poly1305 'secretbox' construction. The authentication
//! tag is prepended to the ciphertext.

use blake2::{
    digest::{consts::U24, Digest},
    Blake2b,
};
use poly1305::{universal_hash::KeyInit, Poly1305};
use salsa20::{
    cipher::{consts::U10, typenum::Unsigned, KeyIvInit, StreamCipher},
    hsalsa, Key as SalsaKey, XSalsa20,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    alg::x25519::X25519KeyPair,
    array::Array,
    buffer::{ResizeBuffer, SecretBytes, WriteBuffer, Writer},
    error::Error,
    repr::{KeyGen, KeyPublicBytes},
};

/// The length of the salsa box nonce
pub const CBOX_NONCE_LENGTH: usize = <XSalsa20 as salsa20::cipher::IvSizeUser>::IvSize::USIZE;
/// The length of the salsa box key (x25519 public key)
pub const CBOX_KEY_LENGTH: usize = crate::alg::x25519::PUBLIC_KEY_LENGTH;
/// The length of the salsa box tag
pub const CBOX_TAG_LENGTH: usize = 16;

/// Derive the shared secretbox key from a key pair and a peer public key
fn shared_key(sk: &X25519KeyPair, pk: &X25519KeyPair) -> Result<Zeroizing<SalsaKey>, Error> {
    let secret = sk
        .secret
        .as_ref()
        .ok_or_else(|| err_msg!(MissingSecretKey))?;
    let shared_secret = secret.diffie_hellman(&pk.public);
    // Like libsodium, reject an all-zero shared secret, which results from a
    // public key of small order
    if !shared_secret.was_contributory() {
        return Err(err_msg!(Encryption, "Invalid public key for crypto box"));
    }
    let shared = Zeroizing::new(shared_secret.to_bytes());
    Ok(Zeroizing::new(hsalsa::<U10>(
        &Array::from(*shared),
        &Array::default(),
    )))
}

/// Initialize the XSalsa20 cipher and Poly1305 MAC for a given key and nonce
fn init_cipher_and_mac(key: &SalsaKey, nonce: &[u8]) -> Result<(XSalsa20, Poly1305), Error> {
    let nonce = nonce.try_into().map_err(|_| err_msg!(InvalidNonce))?;
    let mut cipher = XSalsa20::new(key, nonce);
    // the first 32 bytes of the key stream are used as the MAC key
    let mut mac_key = Zeroizing::new(poly1305::Key::default());
    cipher.apply_keystream(mac_key.as_mut_slice());
    Ok((cipher, Poly1305::new(&mac_key)))
}

/// Encrypt a message into a crypto box with a given nonce
pub fn crypto_box<B: ResizeBuffer>(
    recip_pk: &X25519KeyPair,
    sender_sk: &X25519KeyPair,
    buffer: &mut B,
    nonce: &[u8],
) -> Result<(), Error> {
    let key = shared_key(sender_sk, recip_pk)?;
    let (mut cipher, mac) = init_cipher_and_mac(&key, nonce)?;
    cipher.apply_keystream(buffer.as_mut());
    let tag = mac.compute_unpadded(buffer.as_ref());
    buffer.buffer_insert(0, &tag[..])?;
    Ok(())
}

/// Unencrypt a crypto box
pub fn crypto_box_open<B: ResizeBuffer>(
    recip_sk: &X25519KeyPair,
    sender_pk: &X25519KeyPair,
    buffer: &mut B,
    nonce: &[u8],
) -> Result<(), Error> {
    let key = shared_key(recip_sk, sender_pk)?;
    if buffer.as_ref().len() < CBOX_TAG_LENGTH {
        return Err(err_msg!(Encryption, "Invalid size for encrypted data"));
    }
    let (mut cipher, mac) = init_cipher_and_mac(&key, nonce)?;
    // the tag is prepended
    let expected_tag = mac.compute_unpadded(&buffer.as_ref()[CBOX_TAG_LENGTH..]);
    if !bool::from(
        expected_tag
            .as_slice()
            .ct_eq(&buffer.as_ref()[..CBOX_TAG_LENGTH]),
    ) {
        return Err(err_msg!(Encryption, "Crypto box AEAD decryption error"));
    }
    cipher.apply_keystream(&mut buffer.as_mut()[CBOX_TAG_LENGTH..]);
    buffer.buffer_remove(0..CBOX_TAG_LENGTH)?;
    Ok(())
}

/// Construct a deterministic nonce for an ephemeral and recipient key
pub fn crypto_box_seal_nonce(
    ephemeral_pk: &[u8],
    recip_pk: &[u8],
) -> Result<[u8; CBOX_NONCE_LENGTH], Error> {
    let mut key_hash = Blake2b::<U24>::new();
    key_hash.update(ephemeral_pk);
    key_hash.update(recip_pk);
    Ok(key_hash.finalize().into())
}

/// Encrypt a message for a recipient using an ephemeral key and deterministic nonce
// Could add a non-alloc version, if needed
pub fn crypto_box_seal(recip_pk: &X25519KeyPair, message: &[u8]) -> Result<SecretBytes, Error> {
    let ephem_kp = X25519KeyPair::random()?;
    let ephem_pk_bytes = ephem_kp.public.as_bytes();
    let buf_len = CBOX_KEY_LENGTH + CBOX_TAG_LENGTH + message.len();
    let mut buffer = SecretBytes::with_capacity(buf_len);
    buffer.buffer_write(ephem_pk_bytes)?;
    buffer.buffer_write(message)?;
    let mut writer = Writer::from_vec_skip(buffer.as_vec_mut(), CBOX_KEY_LENGTH);
    let nonce = crypto_box_seal_nonce(ephem_pk_bytes, recip_pk.public.as_bytes())?.to_vec();
    crypto_box(recip_pk, &ephem_kp, &mut writer, &nonce[..])?;
    Ok(buffer)
}

/// Unseal a sealed crypto box
pub fn crypto_box_seal_open(
    recip_sk: &X25519KeyPair,
    ciphertext: &[u8],
) -> Result<SecretBytes, Error> {
    if ciphertext.len() < CBOX_KEY_LENGTH + CBOX_TAG_LENGTH {
        return Err(err_msg!(Encryption, "Invalid size for encrypted data"));
    }
    let ephem_pk = X25519KeyPair::from_public_bytes(&ciphertext[..CBOX_KEY_LENGTH])?;
    let mut buffer = SecretBytes::from_slice(&ciphertext[CBOX_KEY_LENGTH..]);
    let nonce = crypto_box_seal_nonce(ephem_pk.public.as_bytes(), recip_sk.public.as_bytes())?;
    crypto_box_open(recip_sk, &ephem_pk, &mut buffer, &nonce)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::SecretBytes;
    use crate::repr::{KeySecretBytes, ToPublicBytes};

    #[test]
    fn crypto_box_round_trip_expected() {
        let sk = X25519KeyPair::from_secret_bytes(&hex!(
            "a8bdb9830f8790d242f66e04b11cc2a14c752a7b63c073f3c68e9adb151cc854"
        ))
        .unwrap();
        let pk = X25519KeyPair::from_public_bytes(&hex!(
            "07d0b594683bdb6af5f4eacb1a392687d580a58db196a752dca316dedb7d251c"
        ))
        .unwrap();
        let message = b"hello there";
        let nonce = b"012345678912012345678912";
        let mut buffer = SecretBytes::from_slice(message);
        crypto_box(&pk, &sk, &mut buffer, nonce).unwrap();
        assert_eq!(
            buffer,
            &hex!("848dc97d373f7aa2223b57780c60f7731cc8721d567baa8f2b5583")[..]
        );

        crypto_box_open(&sk, &pk, &mut buffer, nonce).unwrap();
        assert_eq!(buffer, &message[..]);
    }

    fn test_keys() -> (X25519KeyPair, X25519KeyPair) {
        let sk = X25519KeyPair::from_secret_bytes(&hex!(
            "a8bdb9830f8790d242f66e04b11cc2a14c752a7b63c073f3c68e9adb151cc854"
        ))
        .unwrap();
        let pk = X25519KeyPair::from_public_bytes(&hex!(
            "07d0b594683bdb6af5f4eacb1a392687d580a58db196a752dca316dedb7d251c"
        ))
        .unwrap();
        (sk, pk)
    }

    const TEST_NONCE: &[u8; 24] = b"012345678912012345678912";

    #[test]
    fn crypto_box_open_tampered() {
        let (sk, pk) = test_keys();
        let mut boxed = SecretBytes::from_slice(b"hello there");
        crypto_box(&pk, &sk, &mut boxed, TEST_NONCE).unwrap();

        // flipping any single bit of the tag or ciphertext must be rejected
        for idx in 0..boxed.len() {
            for bit in 0..8 {
                let mut buffer = boxed.clone();
                buffer.as_mut()[idx] ^= 1 << bit;
                assert!(
                    crypto_box_open(&sk, &pk, &mut buffer, TEST_NONCE).is_err(),
                    "tampered byte {idx} bit {bit} accepted"
                );
            }
        }

        // truncated and extended messages
        let mut buffer = SecretBytes::from_slice(&boxed[..boxed.len() - 1]);
        assert!(crypto_box_open(&sk, &pk, &mut buffer, TEST_NONCE).is_err());
        let mut buffer = boxed.clone();
        buffer.buffer_write(&[0u8]).unwrap();
        assert!(crypto_box_open(&sk, &pk, &mut buffer, TEST_NONCE).is_err());

        // modified or invalid nonce
        let mut nonce = *TEST_NONCE;
        nonce[0] ^= 1;
        let mut buffer = boxed.clone();
        assert!(crypto_box_open(&sk, &pk, &mut buffer, &nonce).is_err());
        let mut buffer = boxed.clone();
        assert!(crypto_box_open(&sk, &pk, &mut buffer, &TEST_NONCE[..23]).is_err());

        // incorrect keys
        let other = X25519KeyPair::random().unwrap();
        let mut buffer = boxed.clone();
        assert!(crypto_box_open(&other, &pk, &mut buffer, TEST_NONCE).is_err());
        let mut buffer = boxed.clone();
        assert!(crypto_box_open(&sk, &other, &mut buffer, TEST_NONCE).is_err());

        // the untouched message still opens
        let mut buffer = boxed.clone();
        crypto_box_open(&sk, &pk, &mut buffer, TEST_NONCE).unwrap();
        assert_eq!(buffer, &b"hello there"[..]);
    }

    #[test]
    fn crypto_box_seal_open_tampered() {
        let recip = X25519KeyPair::random().unwrap();
        let sealed = crypto_box_seal(&recip, b"hello there").unwrap();
        for idx in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered.as_mut()[idx] ^= 0x80;
            assert!(crypto_box_seal_open(&recip, &tampered).is_err());
        }
        crypto_box_seal_open(&recip, &sealed).unwrap();
    }

    #[test]
    fn crypto_box_small_order_public_key() {
        let (sk, _) = test_keys();
        // Low order points (and non-canonical encodings) on Curve25519, which
        // produce an all-zero shared secret
        let small_order: [[u8; 32]; 5] = [
            [0u8; 32],
            hex!("0100000000000000000000000000000000000000000000000000000000000000"),
            hex!("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
            hex!("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
            hex!("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ];
        for bytes in small_order {
            let bad_pk = X25519KeyPair::from_public_bytes(&bytes).unwrap();

            let mut buffer = SecretBytes::from_slice(b"hello there");
            assert!(crypto_box(&bad_pk, &sk, &mut buffer, TEST_NONCE).is_err());
            // the buffer is not modified on failure
            assert_eq!(buffer, &b"hello there"[..]);

            let mut buffer = SecretBytes::from_slice(&[0u8; 32]);
            assert!(crypto_box_open(&sk, &bad_pk, &mut buffer, TEST_NONCE).is_err());
            assert_eq!(buffer, &[0u8; 32][..]);

            // a sealed box to a small order key cannot be created
            assert!(crypto_box_seal(&bad_pk, b"hello there").is_err());
        }
    }

    #[test]
    fn crypto_box_open_too_short() {
        let sk = X25519KeyPair::from_secret_bytes(&hex!(
            "a8bdb9830f8790d242f66e04b11cc2a14c752a7b63c073f3c68e9adb151cc854"
        ))
        .unwrap();
        let pk = X25519KeyPair::from_public_bytes(&hex!(
            "07d0b594683bdb6af5f4eacb1a392687d580a58db196a752dca316dedb7d251c"
        ))
        .unwrap();
        let mut buffer = SecretBytes::from_slice(b"0000000000");
        let nonce = b"012345678912012345678912";
        assert!(crypto_box_open(&sk, &pk, &mut buffer, nonce).is_err());
    }

    #[test]
    fn crypto_box_seal_round_trip() {
        let recip = X25519KeyPair::random().unwrap();

        let recip_public =
            X25519KeyPair::from_public_bytes(recip.to_public_bytes().unwrap().as_ref()).unwrap();

        let message = b"hello there";
        let sealed = crypto_box_seal(&recip_public, message).unwrap();
        assert_ne!(sealed, &message[..]);

        let open = crypto_box_seal_open(&recip, &sealed).unwrap();
        assert_eq!(open, &message[..]);
    }

    #[test]
    fn crypto_box_unseal_expected() {
        use crate::alg::ed25519::Ed25519KeyPair;
        let recip = Ed25519KeyPair::from_secret_bytes(b"testseed000000000000000000000001")
            .unwrap()
            .to_x25519_keypair();
        let ciphertext = hex!(
            "ed443c0377a579857f2f00543e0da0f2585b6119cd9e43c871e4f1114c7ce9050b
            a8811edf39d257bbeec0d423a0a7ff98d424fbfa9d52e0c5b3f674738f75d8e727f
            5526296482fd0fd013d71d50ce4ce5ebe9c2fa1c230298419a9"
        );
        crypto_box_seal_open(&recip, &ciphertext).unwrap();
    }

    #[test]
    fn crypto_box_unseal_too_short() {
        use crate::alg::ed25519::Ed25519KeyPair;
        let recip = Ed25519KeyPair::from_secret_bytes(b"testseed000000000000000000000001")
            .unwrap()
            .to_x25519_keypair();
        let ciphertext = hex!("ed443c0377a0");
        assert!(crypto_box_seal_open(&recip, &ciphertext).is_err());
    }
}
