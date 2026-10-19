use core::fmt::{self, Debug, Formatter};

use crate::array::typenum::Unsigned;

use alloc::boxed::Box;
use ml_dsa::{
    signature::{Signer, Verifier},
    EncodedVerifyingKey, ExpandedSigningKey, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed,
    Signature, VerifyingKey,
};
use rand::TryCryptoRng;
use zeroize::Zeroize;

use super::HasKeyBackend;
use crate::{
    array::{
        sizes::{U1312, U1952, U2592},
        typenum::{Sum, U32},
        ArraySize,
    },
    buffer::{ArrayKey, WriteBuffer},
    error::Error,
    jwk::{FromJwk, JwkEncoder, JwkParts, ToJwk},
    random::KeyMaterial,
    repr::{KeyGen, KeyMeta, KeyPublicBytes, KeySecretBytes, KeypairBytes, KeypairMeta},
    sign::{KeySigVerify, KeySign, SignatureType},
};

pub trait MlDsaVariant: MlDsaParams {
    type PublicKeySize: ArraySize;
    type KeypairSize: ArraySize;
    const JWK_ALG: &'static str;
}

impl MlDsaVariant for MlDsa44 {
    type PublicKeySize = U1312;
    type KeypairSize = Sum<U32, U1312>;
    const JWK_ALG: &'static str = "ML-DSA-44";
}

impl MlDsaVariant for MlDsa65 {
    type PublicKeySize = U1952;
    type KeypairSize = Sum<U32, U1952>;
    const JWK_ALG: &'static str = "ML-DSA-65";
}

impl MlDsaVariant for MlDsa87 {
    type PublicKeySize = U2592;
    type KeypairSize = Sum<U32, U2592>;
    const JWK_ALG: &'static str = "ML-DSA-87";
}

/// ML-DSA key pair (FIPS 204).
///
/// The private key is exported as its 32-byte seed only. The expanded signing
/// key is derived once when loading the seed and retained on the heap for
/// subsequent signatures.
#[derive(Clone)]
pub struct MlDsaKeyPair<P: MlDsaVariant> {
    seed: Option<[u8; 32]>,
    signing: Option<Box<ExpandedSigningKey<P>>>,
    verifying: VerifyingKey<P>,
    public: EncodedVerifyingKey<P>,
}

pub type MlDsa44KeyPair = MlDsaKeyPair<MlDsa44>;
pub type MlDsa65KeyPair = MlDsaKeyPair<MlDsa65>;
pub type MlDsa87KeyPair = MlDsaKeyPair<MlDsa87>;

impl<P: MlDsaVariant> MlDsaKeyPair<P> {
    fn ml_seed(seed: &[u8; 32]) -> Seed {
        let mut ml_seed = Seed::default();
        ml_seed.copy_from_slice(seed);
        ml_seed
    }

    fn from_seed_array(mut seed: [u8; 32]) -> Self {
        let mut ml_seed = Self::ml_seed(&seed);
        let signing = Box::new(ExpandedSigningKey::<P>::from_seed(&ml_seed));
        ml_seed.zeroize();
        let verifying = signing.verifying_key();
        let public = verifying.encode();
        let keypair = Self {
            seed: Some(seed),
            signing: Some(signing),
            verifying,
            public,
        };
        seed.zeroize();
        keypair
    }

    fn from_public(encoded: EncodedVerifyingKey<P>) -> Self {
        let verifying = VerifyingKey::<P>::decode(&encoded);
        Self {
            seed: None,
            signing: None,
            verifying,
            public: encoded,
        }
    }

    fn sign_inner(&self, message: &[u8]) -> Result<Signature<P>, Error> {
        self.signing
            .as_ref()
            .ok_or_else(|| err_msg!(MissingSecretKey))?
            .try_sign(message)
            .map_err(|_| err_msg!(Unexpected, "ML-DSA signing failed"))
    }

    pub fn sign(&self, message: &[u8]) -> Result<Signature<P>, Error> {
        self.sign_inner(message)
    }

    pub fn sign_hedged<R: TryCryptoRng + ?Sized>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Signature<P>, Error> {
        self.signing
            .as_ref()
            .ok_or_else(|| err_msg!(MissingSecretKey))?
            .sign_randomized(message, &[], rng)
            .map_err(|_| err_msg!(Unexpected, "ML-DSA hedged signing failed"))
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, Error> {
        let signature = Signature::<P>::try_from(signature)
            .map_err(|_| err_msg!(Invalid, "Invalid ML-DSA signature"))?;
        Ok(self.verifying.verify(message, &signature).is_ok())
    }
}

impl<P: MlDsaVariant> Debug for MlDsaKeyPair<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaKeyPair")
            .field("algorithm", &P::JWK_ALG)
            .field(
                "seed",
                &if self.seed.is_some() {
                    "<secret>"
                } else {
                    "None"
                },
            )
            .field("public", &self.public)
            .finish()
    }
}

impl<P: MlDsaVariant> HasKeyBackend for MlDsaKeyPair<P> {}

impl<P: MlDsaVariant> KeyMeta for MlDsaKeyPair<P> {
    type KeySize = U32;
}

impl<P: MlDsaVariant> KeypairMeta for MlDsaKeyPair<P> {
    type PublicKeySize = P::PublicKeySize;
    type KeypairSize = P::KeypairSize;
}

impl<P: MlDsaVariant> KeypairBytes for MlDsaKeyPair<P> {
    fn from_keypair_bytes(keypair: &[u8]) -> Result<Self, Error> {
        let expected_len = 32 + P::PublicKeySize::USIZE;
        if keypair.len() != expected_len {
            return Err(err_msg!(InvalidKeyData));
        }

        let key = Self::from_secret_bytes(&keypair[..32])?;
        if key.public[..] != keypair[32..] {
            return Err(err_msg!(InvalidKeyData, "ML-DSA public key mismatch"));
        }
        Ok(key)
    }

    fn with_keypair_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        if let Some(seed) = self.seed.as_ref() {
            ArrayKey::<P::KeypairSize>::temp(|keypair| {
                keypair[..32].copy_from_slice(seed);
                keypair[32..].copy_from_slice(&self.public);
                f(Some(keypair.as_ref()))
            })
        } else {
            f(None)
        }
    }
}

impl<P: MlDsaVariant> KeyGen for MlDsaKeyPair<P> {
    fn generate(mut rng: impl KeyMaterial) -> Result<Self, Error> {
        let mut seed = [0u8; 32];
        rng.read_okm(&mut seed);
        let keypair = Self::from_seed_array(seed);
        seed.zeroize();
        Ok(keypair)
    }
}

impl<P: MlDsaVariant> KeySecretBytes for MlDsaKeyPair<P> {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        let mut seed: [u8; 32] = key.try_into().map_err(|_| err_msg!(InvalidKeyData))?;
        let keypair = Self::from_seed_array(seed);
        seed.zeroize();
        Ok(keypair)
    }

    fn with_secret_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        f(self.seed.as_ref().map(|seed| &seed[..]))
    }
}

impl<P: MlDsaVariant> KeyPublicBytes for MlDsaKeyPair<P> {
    fn from_public_bytes(key: &[u8]) -> Result<Self, Error> {
        let encoded =
            EncodedVerifyingKey::<P>::try_from(key).map_err(|_| err_msg!(InvalidKeyData))?;
        Ok(Self::from_public(encoded))
    }

    fn with_public_bytes<O>(&self, f: impl FnOnce(&[u8]) -> O) -> O {
        f(&self.public)
    }
}

impl<P: MlDsaVariant> KeySign for MlDsaKeyPair<P> {
    fn write_signature(
        &self,
        message: &[u8],
        sig_type: Option<SignatureType>,
        out: &mut dyn WriteBuffer,
    ) -> Result<(), Error> {
        if sig_type.is_some() {
            return Err(err_msg!(Unsupported, "Unsupported signature type"));
        }
        let signature = self.sign_inner(message)?;
        out.buffer_write(&signature.encode())
    }
}

impl<P: MlDsaVariant> KeySigVerify for MlDsaKeyPair<P> {
    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<bool, Error> {
        if sig_type.is_some() {
            return Err(err_msg!(Unsupported, "Unsupported signature type"));
        }
        self.verify(message, signature)
    }
}

impl<P: MlDsaVariant> ToJwk for MlDsaKeyPair<P> {
    fn encode_jwk(&self, enc: &mut dyn JwkEncoder) -> Result<(), Error> {
        enc.add_str("alg", P::JWK_ALG)?;
        enc.add_str("kty", "AKP")?;
        enc.add_as_base64("pub", &self.public)?;
        if enc.is_secret() {
            if let Some(seed) = self.seed.as_ref() {
                enc.add_as_base64("priv", seed)?;
            }
        }
        Ok(())
    }
}

impl<P: MlDsaVariant> FromJwk for MlDsaKeyPair<P> {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        if jwk.kty != "AKP" || jwk.alg != P::JWK_ALG || jwk.pub_key.is_none() {
            return Err(err_msg!(InvalidKeyData, "Invalid ML-DSA JWK"));
        }

        let mut encoded = EncodedVerifyingKey::<P>::default();
        if jwk.pub_key.decode_base64(&mut encoded)? != encoded.len() {
            return Err(err_msg!(InvalidKeyData, "Invalid ML-DSA public key"));
        }

        if jwk.priv_key.is_some() {
            let mut seed = [0u8; 32];
            let decoded = jwk.priv_key.decode_base64(&mut seed);
            let decoded_len = match decoded {
                Ok(decoded_len) => decoded_len,
                Err(err) => {
                    seed.zeroize();
                    return Err(err);
                }
            };
            if decoded_len != seed.len() {
                seed.zeroize();
                return Err(err_msg!(InvalidKeyData, "Invalid ML-DSA seed"));
            }
            let keypair = Self::from_seed_array(seed);
            if keypair.public != encoded {
                return Err(err_msg!(InvalidKeyData, "ML-DSA public key mismatch"));
            }
            Ok(keypair)
        } else {
            Ok(Self::from_public(encoded))
        }
    }
}

impl<P: MlDsaVariant> Drop for MlDsaKeyPair<P> {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        array::typenum::Unsigned,
        buffer::SecretBytes,
        random::RandomDet,
        repr::{KeyPublicBytes, KeySecretBytes, ToPublicBytes, ToSecretBytes},
    };

    fn keypair_round_trip<P: MlDsaVariant>() {
        let keypair = MlDsaKeyPair::<P>::from_secret_bytes(&[0x42; 32]).unwrap();
        assert_eq!(keypair.to_secret_bytes().unwrap().as_ref(), &[0x42; 32]);
        let keypair_bytes = keypair.to_keypair_bytes().unwrap();
        assert_eq!(keypair_bytes.len(), 32 + P::PublicKeySize::USIZE);
        let imported_keypair =
            MlDsaKeyPair::<P>::from_keypair_bytes(keypair_bytes.as_ref()).unwrap();
        assert_eq!(
            imported_keypair.to_secret_bytes().unwrap().as_ref(),
            &[0x42; 32]
        );
        assert!(
            MlDsaKeyPair::<P>::from_keypair_bytes(&keypair_bytes[..keypair_bytes.len() - 1])
                .is_err()
        );
        let mut altered_keypair = keypair_bytes.as_ref().to_vec();
        altered_keypair[32] ^= 1;
        assert!(MlDsaKeyPair::<P>::from_keypair_bytes(&altered_keypair).is_err());

        let mut sig = SecretBytes::with_capacity(5000);
        keypair
            .write_signature(b"ML-DSA test message", None, &mut sig)
            .unwrap();
        assert!(keypair
            .verify_signature(b"ML-DSA test message", sig.as_ref(), None)
            .unwrap());
        assert!(!keypair
            .verify_signature(b"different message", sig.as_ref(), None)
            .unwrap());
        assert_eq!(
            sig.len(),
            match P::JWK_ALG {
                "ML-DSA-44" => 2420,
                "ML-DSA-65" => 3309,
                _ => 4627,
            }
        );

        let deterministic_first = keypair.sign(b"deterministic test").unwrap();
        let deterministic_second = keypair.sign(b"deterministic test").unwrap();
        assert_eq!(deterministic_first, deterministic_second);

        let mut rng = RandomDet::new(b"hedged test seed");
        let hedged_first = keypair.sign_hedged(b"hedged test", &mut rng).unwrap();
        let mut rng = RandomDet::new(b"hedged test seed");
        let hedged_second = keypair.sign_hedged(b"hedged test", &mut rng).unwrap();
        assert_eq!(hedged_first, hedged_second);
        assert!(keypair
            .verify(b"hedged test", &hedged_first.encode())
            .unwrap());
        let mut rng = RandomDet::new(b"different hedged seed");
        let hedged_different = keypair.sign_hedged(b"hedged test", &mut rng).unwrap();
        assert_ne!(hedged_first, hedged_different);
        assert!(keypair
            .verify(b"hedged test", &hedged_different.encode())
            .unwrap());

        let public = keypair.to_public_bytes().unwrap();
        assert_eq!(public.len(), P::PublicKeySize::USIZE);
        let public_key = MlDsaKeyPair::<P>::from_public_bytes(public.as_ref()).unwrap();
        assert!(public_key
            .verify_signature(b"ML-DSA test message", sig.as_ref(), None)
            .unwrap());
        assert!(public_key
            .write_signature(b"message", None, &mut SecretBytes::new_with(0, |_| {}))
            .is_err());

        let secret_jwk = keypair.to_jwk_secret(None).unwrap();
        let parsed = JwkParts::try_from_str(secret_jwk.as_opt_str().unwrap()).unwrap();
        assert!(parsed.pub_key.is_some());
        assert!(parsed.priv_key.is_some());
        let imported = MlDsaKeyPair::<P>::from_jwk_parts(parsed).unwrap();
        assert_eq!(imported.to_secret_bytes().unwrap().as_ref(), &[0x42; 32]);

        let public_jwk = keypair.to_jwk_public(None).unwrap();
        let parsed = JwkParts::try_from_str(&public_jwk).unwrap();
        assert!(parsed.priv_key.is_none());
        let imported = MlDsaKeyPair::<P>::from_jwk_parts(parsed).unwrap();
        assert_eq!(
            imported.to_public_bytes().unwrap().as_ref(),
            public.as_ref()
        );
    }

    #[test]
    fn mldsa44_round_trip() {
        keypair_round_trip::<MlDsa44>();
    }

    #[test]
    fn mldsa65_round_trip() {
        keypair_round_trip::<MlDsa65>();
    }

    #[test]
    fn mldsa87_round_trip() {
        keypair_round_trip::<MlDsa87>();
    }

    #[test]
    fn keypair_stays_small() {
        assert!(core::mem::size_of::<MlDsa87KeyPair>() < 4096);
        assert!(core::mem::size_of::<MlDsa44KeyPair>() < 2048);
    }
}
