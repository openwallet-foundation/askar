//! Elliptic curve ECDH and ECDSA support on curve secp384r1

use core::convert::{TryFrom, TryInto};

use p384::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::{
        self,
        ecdh::diffie_hellman,
        sec1::{Coordinates, FromEncodedPoint, ToEncodedPoint},
    },
    EncodedPoint, PublicKey, SecretKey,
};
use subtle::ConstantTimeEq;

use super::{ec_common, EcCurves, HasKeyAlg, HasKeyBackend, KeyAlg};
use crate::{
    buffer::{ArrayKey, WriteBuffer},
    error::Error,
    generic_array::typenum::{U48, U49, U97},
    jwk::{FromJwk, JwkEncoder, JwkParts, ToJwk},
    kdf::KeyExchange,
    random::KeyMaterial,
    repr::{KeyGen, KeyMeta, KeyPublicBytes, KeySecretBytes, KeypairBytes, KeypairMeta},
    sign::{KeySigVerify, KeySign, SignatureType},
};

// SECURITY: PublicKey contains a p384::AffinePoint, which is always checked
// to be on the curve when loaded.
// The identity point is rejected when converting into a p384::PublicKey.
// This satisfies 5.6.2.3.4 ECC Partial Public-Key Validation Routine from
// NIST SP 800-56A: _Recommendation for Pair-Wise Key-Establishment Schemes
// Using Discrete Logarithm Cryptography_.

/// The length of an ES384 signature
pub const ES384_SIGNATURE_LENGTH: usize = 96;

/// The length of a compressed public key in bytes
pub const PUBLIC_KEY_LENGTH: usize = 49;
/// The length of a secret key
pub const SECRET_KEY_LENGTH: usize = 48;
/// The length of a keypair in bytes
pub const KEYPAIR_LENGTH: usize = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

/// The 'kty' value of an elliptic curve key JWK
pub static JWK_KEY_TYPE: &str = "EC";
/// The 'crv' value of a P-384 key JWK
pub static JWK_CURVE: &str = "P-384";

type FieldSize = elliptic_curve::FieldBytesSize<p384::NistP384>;

/// A P-384 (secp384r1) public key or keypair
#[derive(Clone, Debug)]
pub struct P384KeyPair {
    // SECURITY: SecretKey zeroizes on drop
    secret: Option<SecretKey>,
    public: PublicKey,
}

impl P384KeyPair {
    #[inline]
    pub(crate) fn from_secret_key(sk: SecretKey) -> Self {
        let pk = sk.public_key();
        Self {
            secret: Some(sk),
            public: pk,
        }
    }

    pub(crate) fn check_public_bytes(&self, pk: &[u8]) -> Result<(), Error> {
        if self.with_public_bytes(|slf| slf.ct_eq(pk)).into() {
            Ok(())
        } else {
            Err(err_msg!(InvalidKeyData, "invalid p384 keypair"))
        }
    }

    pub(crate) fn to_signing_key(&self) -> Option<SigningKey> {
        self.secret.clone().map(SigningKey::from)
    }

    /// Sign a message with the secret key
    pub fn sign(&self, message: &[u8]) -> Option<[u8; ES384_SIGNATURE_LENGTH]> {
        if let Some(skey) = self.to_signing_key() {
            let sig: Signature = skey.sign(message);
            let mut sigb = [0u8; 96];
            sigb.copy_from_slice(&sig.to_bytes());
            Some(sigb)
        } else {
            None
        }
    }

    /// Verify a signature with the public key
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        if let Ok(sig) = Signature::try_from(signature) {
            let vk = VerifyingKey::from(&self.public);
            vk.verify(message, &sig).is_ok()
        } else {
            false
        }
    }
}

impl HasKeyBackend for P384KeyPair {}

impl HasKeyAlg for P384KeyPair {
    fn algorithm(&self) -> KeyAlg {
        KeyAlg::EcCurve(EcCurves::Secp384r1)
    }
}

impl KeyMeta for P384KeyPair {
    type KeySize = U48;
}

impl KeyGen for P384KeyPair {
    fn generate(mut rng: impl KeyMaterial) -> Result<Self, Error> {
        ArrayKey::<FieldSize>::temp(|buf| loop {
            rng.read_okm(buf);
            if let Ok(key) = SecretKey::from_bytes(buf) {
                return Ok(Self::from_secret_key(key));
            }
        })
    }
}

impl KeySecretBytes for P384KeyPair {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        #[allow(clippy::unnecessary_fallible_conversions)]
        if let Ok(key) = key.try_into() {
            if let Ok(sk) = SecretKey::from_bytes(key) {
                return Ok(Self::from_secret_key(sk));
            }
        }
        Err(err_msg!(InvalidKeyData))
    }

    fn with_secret_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        if let Some(sk) = self.secret.as_ref() {
            ArrayKey::<FieldSize>::temp(|arr| {
                ec_common::write_sk(sk, &mut arr[..]);
                f(Some(arr))
            })
        } else {
            f(None)
        }
    }
}

impl KeypairMeta for P384KeyPair {
    type PublicKeySize = U49;
    type KeypairSize = U97;
}

impl KeypairBytes for P384KeyPair {
    fn from_keypair_bytes(kp: &[u8]) -> Result<Self, Error> {
        if kp.len() != KEYPAIR_LENGTH {
            return Err(err_msg!(InvalidKeyData));
        }
        let result = P384KeyPair::from_secret_bytes(&kp[..SECRET_KEY_LENGTH])
            .map_err(|_| err_msg!(InvalidKeyData))?;
        result.check_public_bytes(&kp[SECRET_KEY_LENGTH..])?;
        Ok(result)
    }

    fn with_keypair_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        if let Some(sk) = self.secret.as_ref() {
            ArrayKey::<<Self as KeypairMeta>::KeypairSize>::temp(|arr| {
                ec_common::write_sk(sk, &mut arr[..SECRET_KEY_LENGTH]);
                let pk_enc = self.public.to_encoded_point(true);
                arr[SECRET_KEY_LENGTH..].copy_from_slice(pk_enc.as_bytes());
                f(Some(&*arr))
            })
        } else {
            f(None)
        }
    }
}

impl KeyPublicBytes for P384KeyPair {
    fn from_public_bytes(key: &[u8]) -> Result<Self, Error> {
        let pk = PublicKey::from_sec1_bytes(key).map_err(|_| err_msg!(InvalidKeyData))?;
        Ok(Self {
            secret: None,
            public: pk,
        })
    }

    fn with_public_bytes<O>(&self, f: impl FnOnce(&[u8]) -> O) -> O {
        f(self.public.to_encoded_point(true).as_bytes())
    }
}

impl KeySign for P384KeyPair {
    fn write_signature(
        &self,
        message: &[u8],
        sig_type: Option<SignatureType>,
        out: &mut dyn WriteBuffer,
    ) -> Result<(), Error> {
        match sig_type {
            None | Some(SignatureType::ES384) => {
                if let Some(sig) = self.sign(message) {
                    out.buffer_write(&sig[..])?;
                    Ok(())
                } else {
                    Err(err_msg!(Unsupported, "Undefined secret key"))
                }
            }
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

impl KeySigVerify for P384KeyPair {
    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<bool, Error> {
        match sig_type {
            None | Some(SignatureType::ES384) => Ok(self.verify_signature(message, signature)),
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

impl ToJwk for P384KeyPair {
    fn encode_jwk(&self, enc: &mut dyn JwkEncoder) -> Result<(), Error> {
        let pk_enc = self.public.to_encoded_point(false);
        let (x, y) = match pk_enc.coordinates() {
            Coordinates::Identity => {
                return Err(err_msg!(
                    Unsupported,
                    "Cannot convert identity point to JWK"
                ))
            }
            Coordinates::Uncompressed { x, y } => (x, y),
            Coordinates::Compressed { .. } | Coordinates::Compact { .. } => unreachable!(),
        };

        enc.add_str("crv", JWK_CURVE)?;
        enc.add_str("kty", JWK_KEY_TYPE)?;
        enc.add_as_base64("x", &x[..])?;
        enc.add_as_base64("y", &y[..])?;
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

impl FromJwk for P384KeyPair {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        if jwk.kty != JWK_KEY_TYPE {
            return Err(err_msg!(InvalidKeyData, "Unsupported key type"));
        }
        if jwk.crv != JWK_CURVE {
            return Err(err_msg!(InvalidKeyData, "Unsupported key algorithm"));
        }
        let pk_x = ArrayKey::<FieldSize>::try_new_with(|arr| {
            if jwk.x.decode_base64(arr)? != arr.len() {
                Err(err_msg!(InvalidKeyData))
            } else {
                Ok(())
            }
        })?;
        let pk_y = ArrayKey::<FieldSize>::try_new_with(|arr| {
            if jwk.y.decode_base64(arr)? != arr.len() {
                Err(err_msg!(InvalidKeyData))
            } else {
                Ok(())
            }
        })?;
        let pk = Option::from(PublicKey::from_encoded_point(
            &EncodedPoint::from_affine_coordinates(pk_x.as_ref(), pk_y.as_ref(), false),
        ))
        .ok_or_else(|| err_msg!(InvalidKeyData))?;
        if jwk.d.is_some() {
            ArrayKey::<FieldSize>::temp(|arr| {
                if jwk.d.decode_base64(arr)? != arr.len() {
                    Err(err_msg!(InvalidKeyData))
                } else {
                    let kp = P384KeyPair::from_secret_bytes(arr)?;
                    if kp.public != pk {
                        Err(err_msg!(InvalidKeyData))
                    } else {
                        Ok(kp)
                    }
                }
            })
        } else {
            Ok(Self {
                secret: None,
                public: pk,
            })
        }
    }
}

impl KeyExchange for P384KeyPair {
    fn write_key_exchange(&self, other: &Self, out: &mut dyn WriteBuffer) -> Result<(), Error> {
        match self.secret.as_ref() {
            Some(sk) => {
                let xk = diffie_hellman(sk.to_nonzero_scalar(), other.public.as_affine());
                out.buffer_write(xk.raw_secret_bytes().as_ref())?;
                Ok(())
            }
            None => Err(err_msg!(MissingSecretKey)),
        }
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
        //   "kty": "EC",
        //   "x": "p3ZI8DAmxn8BJ3936Y5MHRLXTAg6SxCNhuH6JBEuieuicUY9wqZk8C63SZIj4htA",
        //   "y": "eqSjvs1X7eI9V2o8sYUpsrj6WUKOymqFtkCxMwWQuDPtZKOHC3fSWkjQvf_73GH-",
        //   "crv": "P-384",
        //   "d": "rgFYq-b_toGb-wN3URCk_e-6Sj2PtUvoefF284q9oKnVCi7sglAmCZkOv-2nOAeE"
        // }
        let test_pvt_b64 = "rgFYq-b_toGb-wN3URCk_e-6Sj2PtUvoefF284q9oKnVCi7sglAmCZkOv-2nOAeE";
        let test_pub_b64 = (
            "p3ZI8DAmxn8BJ3936Y5MHRLXTAg6SxCNhuH6JBEuieuicUY9wqZk8C63SZIj4htA",
            "eqSjvs1X7eI9V2o8sYUpsrj6WUKOymqFtkCxMwWQuDPtZKOHC3fSWkjQvf_73GH-",
        );
        let test_pvt = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(test_pvt_b64)
            .unwrap();
        let sk = P384KeyPair::from_secret_bytes(&test_pvt).expect("Error creating signing key");

        let jwk = sk.to_jwk_public(None).expect("Error converting key to JWK");
        let jwk = JwkParts::try_from_str(&jwk).expect("Error parsing JWK");
        assert_eq!(jwk.kty, JWK_KEY_TYPE);
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, test_pub_b64.0);
        assert_eq!(jwk.y, test_pub_b64.1);
        assert_eq!(jwk.d, None);
        let pk_load = P384KeyPair::from_jwk_parts(jwk).unwrap();
        assert_eq!(sk.to_public_bytes(), pk_load.to_public_bytes());

        let jwk = sk.to_jwk_secret(None).expect("Error converting key to JWK");
        let jwk = JwkParts::from_slice(&jwk).expect("Error parsing JWK");
        assert_eq!(jwk.kty, JWK_KEY_TYPE);
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, test_pub_b64.0);
        assert_eq!(jwk.y, test_pub_b64.1);
        assert_eq!(jwk.d, test_pvt_b64);
        let sk_load = P384KeyPair::from_jwk_parts(jwk).unwrap();
        assert_eq!(
            sk.to_keypair_bytes().unwrap(),
            sk_load.to_keypair_bytes().unwrap()
        );
    }

    #[test]
    fn jwk_thumbprint() {
        let pk = P384KeyPair::from_jwk(
            r#"{
                "kty": "EC",
                "x": "p3ZI8DAmxn8BJ3936Y5MHRLXTAg6SxCNhuH6JBEuieuicUY9wqZk8C63SZIj4htA",
                "y": "eqSjvs1X7eI9V2o8sYUpsrj6WUKOymqFtkCxMwWQuDPtZKOHC3fSWkjQvf_73GH-",
                "crv": "P-384"
            }"#,
        )
        .unwrap();
        assert_eq!(
            pk.to_jwk_thumbprint(None).unwrap(),
            "4zlc15_l012-r5pFk7mnEFs6MghkhSAkdMeNeyL00u4"
        );
    }

    #[test]
    fn sign_verify_expected() {
        let test_msg = b"This is a dummy message for use with tests";
        let test_sig = &hex!(
            "acf7e9f0975738d446b26aa1651ad699cac490a496d6f70221126c35d8e4fcc5a28f63f611557be9d4c321d8fa24dbf2
             846e3bcbea2e45eff577974664b1e98fffdad8ddbe7bfa792c17a9981915aa63755cfd338fd28874de02c42d966ece67"
        );
        let test_pvt = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode("rgFYq-b_toGb-wN3URCk_e-6Sj2PtUvoefF284q9oKnVCi7sglAmCZkOv-2nOAeE")
            .unwrap();
        let kp = P384KeyPair::from_secret_bytes(&test_pvt).unwrap();
        let sig = kp.sign(&test_msg[..]).unwrap();
        assert_eq!(sig, &test_sig[..]);
        assert!(kp.verify_signature(&test_msg[..], &sig[..]));
        assert!(!kp.verify_signature(b"Not the message", &sig[..]));
        assert!(!kp.verify_signature(&test_msg[..], &[0u8; 96]));
    }

    #[test]
    fn key_exchange_random() {
        let kp1 = P384KeyPair::random().unwrap();
        let kp2 = P384KeyPair::random().unwrap();
        assert_ne!(
            kp1.to_keypair_bytes().unwrap(),
            kp2.to_keypair_bytes().unwrap()
        );

        let xch1 = kp1.key_exchange_bytes(&kp2).unwrap();
        let xch2 = kp2.key_exchange_bytes(&kp1).unwrap();
        assert_eq!(xch1.len(), 48);
        assert_eq!(xch1, xch2);
    }

    #[test]
    fn round_trip_bytes() {
        let kp = P384KeyPair::random().unwrap();
        let cmp = P384KeyPair::from_keypair_bytes(&kp.to_keypair_bytes().unwrap()).unwrap();
        assert_eq!(
            kp.to_keypair_bytes().unwrap(),
            cmp.to_keypair_bytes().unwrap()
        );
    }
}
