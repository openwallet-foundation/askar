//! X25519 key exchange support on Curve25519

use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Formatter},
};

use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret as SecretKey};
use zeroize::Zeroizing;

use super::{ed25519::Ed25519KeyPair, HasKeyAlg, HasKeyBackend, KeyAlg};
use crate::{
    buffer::{ArrayKey, WriteBuffer},
    error::Error,
    generic_array::typenum::{U32, U64},
    jwk::{FromJwk, JwkEncoder, JwkParts, ToJwk},
    kdf::KeyExchange,
    random::KeyMaterial,
    repr::{KeyGen, KeyMeta, KeyPublicBytes, KeySecretBytes, KeypairBytes, KeypairMeta},
};

// FIXME: reject low-order points?
// <https://github.com/tendermint/tmkms/pull/279>
// vs. <https://cr.yp.to/ecdh.html> which indicates that all points are safe for normal D-H.

/// The length of a public key in bytes
pub const PUBLIC_KEY_LENGTH: usize = 32;
/// The length of a secret key in bytes
pub const SECRET_KEY_LENGTH: usize = 32;
/// The length of a keypair in bytes
pub const KEYPAIR_LENGTH: usize = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

/// The 'kty' value of an X25519 JWK
pub const JWK_KEY_TYPE: &str = "OKP";
/// The 'crv' value of an X25519 JWK
pub const JWK_CURVE: &str = "X25519";

/// An X25519 public key or keypair
#[derive(Clone)]
pub struct X25519KeyPair {
    // SECURITY: SecretKey (StaticSecret) zeroizes on drop
    pub(crate) secret: Option<SecretKey>,
    pub(crate) public: PublicKey,
}

impl X25519KeyPair {
    #[inline(always)]
    pub(crate) fn new(sk: Option<SecretKey>, pk: PublicKey) -> Self {
        Self {
            secret: sk,
            public: pk,
        }
    }

    #[inline]
    pub(crate) fn from_secret_key(sk: SecretKey) -> Self {
        let public = PublicKey::from(&sk);
        Self {
            secret: Some(sk),
            public,
        }
    }

    pub(crate) fn check_public_bytes(&self, pk: &[u8]) -> Result<(), Error> {
        if self.public.as_bytes().ct_eq(pk).into() {
            Ok(())
        } else {
            Err(err_msg!(InvalidKeyData, "invalid x25519 keypair"))
        }
    }
}

impl Debug for X25519KeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("X25519KeyPair")
            .field(
                "secret",
                if self.secret.is_some() {
                    &"<secret>"
                } else {
                    &"None"
                },
            )
            .field("public", &self.public)
            .finish()
    }
}

impl HasKeyBackend for X25519KeyPair {}

impl HasKeyAlg for X25519KeyPair {
    fn algorithm(&self) -> KeyAlg {
        KeyAlg::X25519
    }
}

impl KeyMeta for X25519KeyPair {
    type KeySize = U32;
}

impl KeyGen for X25519KeyPair {
    fn generate(rng: impl KeyMaterial) -> Result<Self, Error> {
        let sk = ArrayKey::<U32>::generate(rng);
        let sk = SecretKey::from(*<&[u8; SECRET_KEY_LENGTH]>::try_from(&sk).unwrap());
        let pk = PublicKey::from(&sk);
        Ok(Self::new(Some(sk), pk))
    }
}

impl KeySecretBytes for X25519KeyPair {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        let sk: &[u8; SECRET_KEY_LENGTH] = key.try_into().map_err(|_| err_msg!(InvalidKeyData))?;
        Ok(Self::from_secret_key(SecretKey::from(*sk)))
    }

    fn with_secret_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        if let Some(sk) = self.secret.as_ref() {
            let b = Zeroizing::new(sk.to_bytes());
            f(Some(&b[..]))
        } else {
            f(None)
        }
    }
}

impl KeypairMeta for X25519KeyPair {
    type PublicKeySize = U32;
    type KeypairSize = U64;
}

impl KeypairBytes for X25519KeyPair {
    fn from_keypair_bytes(kp: &[u8]) -> Result<Self, Error> {
        if kp.len() != KEYPAIR_LENGTH {
            return Err(err_msg!(InvalidKeyData));
        }
        let result = Self::from_secret_bytes(&kp[..SECRET_KEY_LENGTH])?;
        result.check_public_bytes(&kp[SECRET_KEY_LENGTH..])?;
        Ok(result)
    }

    fn with_keypair_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        if let Some(secret) = self.secret.as_ref() {
            ArrayKey::<<Self as KeypairMeta>::KeypairSize>::temp(|arr| {
                arr[..SECRET_KEY_LENGTH].copy_from_slice(secret.as_bytes());
                arr[SECRET_KEY_LENGTH..].copy_from_slice(self.public.as_bytes());
                f(Some(&*arr))
            })
        } else {
            f(None)
        }
    }
}

impl KeyPublicBytes for X25519KeyPair {
    fn from_public_bytes(key: &[u8]) -> Result<Self, Error> {
        let pk: &[u8; PUBLIC_KEY_LENGTH] = key.try_into().map_err(|_| err_msg!(InvalidKeyData))?;
        Ok(Self::new(None, PublicKey::from(*pk)))
    }

    fn with_public_bytes<O>(&self, f: impl FnOnce(&[u8]) -> O) -> O {
        f(&self.public.to_bytes()[..])
    }
}

impl ToJwk for X25519KeyPair {
    fn encode_jwk(&self, enc: &mut dyn JwkEncoder) -> Result<(), Error> {
        enc.add_str("crv", JWK_CURVE)?;
        enc.add_str("kty", JWK_KEY_TYPE)?;
        self.with_public_bytes(|buf| enc.add_as_base64("x", buf))?;
        if enc.is_secret() {
            self.with_secret_bytes(|buf| {
                if let Some(sk) = buf {
                    enc.add_as_base64("d", sk)
                } else {
                    Ok(())
                }
            })?;
        }
        Ok(())
    }
}

impl FromJwk for X25519KeyPair {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        if jwk.kty != JWK_KEY_TYPE {
            return Err(err_msg!(InvalidKeyData, "Unsupported key type"));
        }
        if jwk.crv != JWK_CURVE {
            return Err(err_msg!(InvalidKeyData, "Unsupported key algorithm"));
        }
        ArrayKey::<U32>::temp(|pk_arr| {
            if jwk.x.decode_base64(pk_arr)? != pk_arr.len() {
                Err(err_msg!(InvalidKeyData))
            } else if jwk.d.is_some() {
                ArrayKey::<U32>::temp(|sk_arr| {
                    if jwk.d.decode_base64(sk_arr)? != sk_arr.len() {
                        Err(err_msg!(InvalidKeyData))
                    } else {
                        let kp = X25519KeyPair::from_secret_bytes(sk_arr)?;
                        kp.check_public_bytes(pk_arr)?;
                        Ok(kp)
                    }
                })
            } else {
                X25519KeyPair::from_public_bytes(pk_arr)
            }
        })
    }
}

impl KeyExchange for X25519KeyPair {
    fn write_key_exchange(&self, other: &Self, out: &mut dyn WriteBuffer) -> Result<(), Error> {
        match self.secret.as_ref() {
            Some(sk) => {
                let xk = sk.diffie_hellman(&other.public);
                out.buffer_write(xk.as_bytes())?;
                Ok(())
            }
            None => Err(err_msg!(MissingSecretKey)),
        }
    }
}

impl TryFrom<&Ed25519KeyPair> for X25519KeyPair {
    type Error = Error;

    fn try_from(value: &Ed25519KeyPair) -> Result<Self, Self::Error> {
        Ok(value.to_x25519_keypair())
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;
    use crate::repr::ToPublicBytes;

    #[test]
    fn jwk_expected() {
        // {
        //   "kty": "OKP",
        //   "d": "qL25gw-HkNJC9m4EsRzCoUx1KntjwHPzxo6a2xUcyFQ",
        //   "use": "enc",
        //   "crv": "X25519",
        //   "x": "tGskN_ae61DP4DLY31_fjkbvnKqf-ze7kA6Cj2vyQxU"
        // }
        let test_pvt_b64 = "qL25gw-HkNJC9m4EsRzCoUx1KntjwHPzxo6a2xUcyFQ";
        let test_pvt = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(test_pvt_b64)
            .unwrap();
        let kp =
            X25519KeyPair::from_secret_bytes(&test_pvt).expect("Error creating x25519 keypair");
        let jwk = kp
            .to_jwk_public(None)
            .expect("Error converting public key to JWK");
        let jwk = JwkParts::try_from_str(&jwk).expect("Error parsing JWK output");
        assert_eq!(jwk.kty, JWK_KEY_TYPE);
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, "tGskN_ae61DP4DLY31_fjkbvnKqf-ze7kA6Cj2vyQxU");
        assert_eq!(jwk.d, None);
        let pk_load = X25519KeyPair::from_jwk_parts(jwk).unwrap();
        assert_eq!(kp.to_public_bytes(), pk_load.to_public_bytes());

        let jwk = kp
            .to_jwk_secret(None)
            .expect("Error converting private key to JWK");
        let jwk = JwkParts::from_slice(&jwk).expect("Error parsing JWK output");
        assert_eq!(jwk.kty, JWK_KEY_TYPE);
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, "tGskN_ae61DP4DLY31_fjkbvnKqf-ze7kA6Cj2vyQxU");
        assert_eq!(jwk.d, test_pvt_b64);
        let sk_load = X25519KeyPair::from_jwk_parts(jwk).unwrap();
        assert_eq!(
            kp.to_keypair_bytes().unwrap(),
            sk_load.to_keypair_bytes().unwrap()
        );
    }

    #[test]
    fn key_exchange_random() {
        let kp1 = X25519KeyPair::random().unwrap();
        let kp2 = X25519KeyPair::random().unwrap();
        assert_ne!(
            kp1.to_keypair_bytes().unwrap(),
            kp2.to_keypair_bytes().unwrap()
        );

        let xch1 = kp1.key_exchange_bytes(&kp2).unwrap();
        let xch2 = kp2.key_exchange_bytes(&kp1).unwrap();
        assert_eq!(xch1.len(), 32);
        assert_eq!(xch1, xch2);
    }

    #[test]
    fn round_trip_bytes() {
        let kp = X25519KeyPair::random().unwrap();
        let cmp = X25519KeyPair::from_keypair_bytes(&kp.to_keypair_bytes().unwrap()).unwrap();
        assert_eq!(
            kp.to_keypair_bytes().unwrap(),
            cmp.to_keypair_bytes().unwrap()
        );
    }
}
