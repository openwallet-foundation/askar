use alloc::{boxed::Box, sync::Arc};
use core::{
    any::{Any, TypeId},
    fmt::Debug,
    panic::{RefUnwindSafe, UnwindSafe},
};

#[cfg(feature = "aes")]
use super::{
    aes::{A128CbcHs256, A128Gcm, A128Kw, A256CbcHs512, A256Gcm, A256Kw, AesKey, AesType},
    AesTypes,
};

#[cfg(feature = "bls")]
use super::{
    bls::{BlsKeyPair, BlsPublicKeyType, G1, G1G2, G2},
    BlsCurves,
};

#[cfg(feature = "chacha")]
use super::{
    chacha20::{Chacha20Key, Chacha20Type, C20P, XC20P},
    Chacha20Types,
};

#[cfg(feature = "ed25519")]
use super::ed25519::{self, Ed25519KeyPair};
#[cfg(feature = "ed25519")]
use super::x25519::{self, X25519KeyPair};

#[cfg(feature = "k256")]
use super::k256::{self, K256KeyPair};

#[cfg(feature = "p256")]
use super::p256::{self, P256KeyPair};

#[cfg(feature = "p384")]
use super::p384::{self, P384KeyPair};

#[cfg(feature = "p256_hardware")]
use super::p256_hardware::P256HardwareKeyPair;

use super::{HasKeyAlg, HasKeyBackend, KeyAlg};
use crate::{
    backend::KeyBackend,
    buffer::{ResizeBuffer, SecretBytes, WriteBuffer},
    encrypt::{KeyAeadInPlace, KeyAeadParams},
    error::Error,
    jwk::{FromJwk, JwkEncoder, JwkParts, ToJwk},
    kdf::{KeyDerivation, KeyExchange},
    random::KeyMaterial,
    repr::{KeyGen, KeyPublicBytes, KeySecretBytes, ToPublicBytes, ToSecretBytes},
    sign::{KeySigVerify, KeySign, SignatureType},
};

#[cfg(any(
    feature = "k256",
    feature = "p256",
    feature = "p384",
    feature = "p256_hardware"
))]
use super::EcCurves;

#[cfg(any(feature = "aes", feature = "chacha"))]
use crate::kdf::{FromKeyDerivation, FromKeyExchange};

#[derive(Debug)]
pub struct KeyT<T: AnyKeyAlg + Send + Sync + RefUnwindSafe + UnwindSafe + ?Sized>(T);

/// The type-erased representation for a concrete key instance
pub type AnyKey = KeyT<dyn AnyKeyAlg + Send + Sync + RefUnwindSafe + UnwindSafe>;

impl AnyKey {
    pub fn algorithm(&self) -> KeyAlg {
        self.0.algorithm()
    }

    pub fn backend(&self) -> KeyBackend {
        self.0.key_backend()
    }

    fn assume<K: AnyKeyAlg>(&self) -> &K {
        self.downcast_ref().expect("Error assuming key type")
    }

    #[inline]
    pub fn downcast_ref<K: AnyKeyAlg>(&self) -> Option<&K> {
        self.0.as_any().downcast_ref()
    }

    #[inline]
    pub fn key_type_id(&self) -> TypeId {
        self.0.as_any().type_id()
    }

    #[inline]
    pub fn key_id(&self) -> Result<SecretBytes, Error> {
        get_key_id_any(self)
    }
}

/// Create `AnyKey` instances from various sources
pub trait AnyKeyCreate: Sized {
    /// Generate a new key from a key material generator for the given key algorithm.
    fn generate_with_rng(alg: KeyAlg, rng: impl KeyMaterial) -> Result<Self, Error>;

    /// Generate a new key with an id for the given key algorithm.
    fn generate_for_hardware(alg: KeyAlg) -> Result<Self, Error>;

    /// Get a key by id for hardware-based key
    fn get_with_id(alg: KeyAlg, id: &str) -> Result<Self, Error>;

    /// Generate a new random key for the given key algorithm.
    #[cfg(feature = "getrandom")]
    fn random(alg: KeyAlg) -> Result<Self, Error> {
        Self::generate_with_rng(alg, crate::random::default_rng())
    }

    /// Generate a new random key for the given key algorithm.
    fn random_det(alg: KeyAlg, seed: &[u8]) -> Result<Self, Error> {
        Self::generate_with_rng(alg, crate::random::RandomDet::new(seed))
    }

    /// Load a public key from its byte representation
    fn from_public_bytes(alg: KeyAlg, public: &[u8]) -> Result<Self, Error>;

    /// Load a secret key or keypair from its byte representation
    fn from_secret_bytes(alg: KeyAlg, secret: &[u8]) -> Result<Self, Error>;

    /// Convert from a concrete key instance
    fn from_key<K: HasKeyAlg + HasKeyBackend + Send + Sync + RefUnwindSafe + UnwindSafe + 'static>(
        key: K,
    ) -> Self;

    /// Create a new key instance from a key exchange
    fn from_key_exchange<Sk, Pk>(alg: KeyAlg, secret: &Sk, public: &Pk) -> Result<Self, Error>
    where
        Sk: KeyExchange<Pk> + ?Sized,
        Pk: ?Sized;

    /// Create a new key instance from a key derivation
    fn from_key_derivation(alg: KeyAlg, derive: impl KeyDerivation) -> Result<Self, Error>;

    /// Derive the corresponding key for the provided key algorithm
    fn convert_key(&self, alg: KeyAlg) -> Result<Self, Error>;
}

impl AnyKeyCreate for Box<AnyKey> {
    fn generate_with_rng(alg: KeyAlg, rng: impl KeyMaterial) -> Result<Self, Error> {
        generate_any_with_rng(alg, rng)
    }

    fn generate_for_hardware(alg: KeyAlg) -> Result<Self, Error> {
        generate_any_for_hardware(alg)
    }

    fn get_with_id(alg: KeyAlg, id: &str) -> Result<Self, Error> {
        get_any_with_id(alg, id)
    }

    fn from_public_bytes(alg: KeyAlg, public: &[u8]) -> Result<Self, Error> {
        from_public_bytes_any(alg, public)
    }

    fn from_secret_bytes(alg: KeyAlg, secret: &[u8]) -> Result<Self, Error> {
        from_secret_bytes_any(alg, secret)
    }

    #[inline(always)]
    fn from_key<
        K: HasKeyAlg + HasKeyBackend + Send + Sync + RefUnwindSafe + UnwindSafe + 'static,
    >(
        key: K,
    ) -> Self {
        Box::new(KeyT(key))
    }

    fn from_key_exchange<Sk, Pk>(alg: KeyAlg, secret: &Sk, public: &Pk) -> Result<Self, Error>
    where
        Sk: KeyExchange<Pk> + ?Sized,
        Pk: ?Sized,
    {
        from_key_exchange_any(alg, secret, public)
    }

    fn from_key_derivation(alg: KeyAlg, derive: impl KeyDerivation) -> Result<Self, Error> {
        from_key_derivation_any(alg, derive)
    }

    fn convert_key(&self, alg: KeyAlg) -> Result<Self, Error> {
        convert_key_any(self, alg)
    }
}

impl AnyKeyCreate for Arc<AnyKey> {
    fn generate_with_rng(alg: KeyAlg, rng: impl KeyMaterial) -> Result<Self, Error> {
        generate_any_with_rng(alg, rng)
    }

    fn generate_for_hardware(alg: KeyAlg) -> Result<Self, Error> {
        generate_any_for_hardware(alg)
    }

    fn get_with_id(alg: KeyAlg, id: &str) -> Result<Self, Error> {
        get_any_with_id(alg, id)
    }

    fn from_public_bytes(alg: KeyAlg, public: &[u8]) -> Result<Self, Error> {
        from_public_bytes_any(alg, public)
    }

    fn from_secret_bytes(alg: KeyAlg, secret: &[u8]) -> Result<Self, Error> {
        from_secret_bytes_any(alg, secret)
    }

    #[inline(always)]
    fn from_key<
        K: HasKeyAlg + HasKeyBackend + Send + Sync + RefUnwindSafe + UnwindSafe + 'static,
    >(
        key: K,
    ) -> Self {
        Arc::new(KeyT(key))
    }

    fn from_key_exchange<Sk, Pk>(alg: KeyAlg, secret: &Sk, public: &Pk) -> Result<Self, Error>
    where
        Sk: KeyExchange<Pk> + ?Sized,
        Pk: ?Sized,
    {
        from_key_exchange_any(alg, secret, public)
    }

    fn from_key_derivation(alg: KeyAlg, derive: impl KeyDerivation) -> Result<Self, Error> {
        from_key_derivation_any(alg, derive)
    }

    fn convert_key(&self, alg: KeyAlg) -> Result<Self, Error> {
        convert_key_any(self, alg)
    }
}

#[inline]
fn generate_any_with_rng<R: AllocKey>(alg: KeyAlg, rng: impl KeyMaterial) -> Result<R, Error> {
    match alg {
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128Gcm) => AesKey::<A128Gcm>::generate(rng).map(R::alloc_key),
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256Gcm) => AesKey::<A256Gcm>::generate(rng).map(R::alloc_key),
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128CbcHs256) => {
            AesKey::<A128CbcHs256>::generate(rng).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256CbcHs512) => {
            AesKey::<A256CbcHs512>::generate(rng).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128Kw) => AesKey::<A128Kw>::generate(rng).map(R::alloc_key),
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256Kw) => AesKey::<A256Kw>::generate(rng).map(R::alloc_key),
        #[cfg(feature = "bls")]
        KeyAlg::Bls12_381(BlsCurves::G1) => BlsKeyPair::<G1>::generate(rng).map(R::alloc_key),
        #[cfg(feature = "bls")]
        KeyAlg::Bls12_381(BlsCurves::G2) => BlsKeyPair::<G2>::generate(rng).map(R::alloc_key),
        #[cfg(feature = "bls")]
        KeyAlg::Bls12_381(BlsCurves::G1G2) => BlsKeyPair::<G1G2>::generate(rng).map(R::alloc_key),
        #[cfg(feature = "chacha")]
        KeyAlg::Chacha20(Chacha20Types::C20P) => {
            Chacha20Key::<C20P>::generate(rng).map(R::alloc_key)
        }
        #[cfg(feature = "chacha")]
        KeyAlg::Chacha20(Chacha20Types::XC20P) => {
            Chacha20Key::<XC20P>::generate(rng).map(R::alloc_key)
        }
        #[cfg(feature = "ed25519")]
        KeyAlg::Ed25519 => Ed25519KeyPair::generate(rng).map(R::alloc_key),
        #[cfg(feature = "ed25519")]
        KeyAlg::X25519 => X25519KeyPair::generate(rng).map(R::alloc_key),
        #[cfg(feature = "k256")]
        KeyAlg::EcCurve(EcCurves::Secp256k1) => K256KeyPair::generate(rng).map(R::alloc_key),
        #[cfg(feature = "p256")]
        KeyAlg::EcCurve(EcCurves::Secp256r1) => P256KeyPair::generate(rng).map(R::alloc_key),
        #[cfg(feature = "p384")]
        KeyAlg::EcCurve(EcCurves::Secp384r1) => P384KeyPair::generate(rng).map(R::alloc_key),
        #[allow(unreachable_patterns)]
        _ => Err(err_msg!(
            Unsupported,
            "Unsupported algorithm for key generation with rng"
        )),
    }
}

#[inline]
fn generate_any_for_hardware<R: AllocKey>(alg: KeyAlg) -> Result<R, Error> {
    match alg {
        #[cfg(feature = "p256_hardware")]
        KeyAlg::EcCurve(EcCurves::Secp256r1) => P256HardwareKeyPair::generate(
            uuid::Uuid::new_v4()
                .hyphenated()
                .encode_lower(&mut uuid::Uuid::encode_buffer()),
        )
        .map(R::alloc_key),
        _ => Err(err_msg!(
            Unsupported,
            "Unsupported algorithm for key generation with id"
        )),
    }
}

#[inline]
fn get_any_with_id<R: AllocKey>(alg: KeyAlg, _id: &str) -> Result<R, Error> {
    let key = match alg {
        #[cfg(feature = "p256_hardware")]
        KeyAlg::EcCurve(EcCurves::Secp256r1) => P256HardwareKeyPair::from_id(_id).map(R::alloc_key),
        _ => Err(err_msg!(
            Unsupported,
            "Unsupported algorithm for key retrieval by id"
        )),
    }?;

    Ok(key)
}

#[inline]
fn from_public_bytes_any<R: AllocKey>(alg: KeyAlg, public: &[u8]) -> Result<R, Error> {
    match alg {
        #[cfg(feature = "bls")]
        KeyAlg::Bls12_381(BlsCurves::G1) => {
            BlsKeyPair::<G1>::from_public_bytes(public).map(R::alloc_key)
        }
        #[cfg(feature = "bls")]
        KeyAlg::Bls12_381(BlsCurves::G2) => {
            BlsKeyPair::<G2>::from_public_bytes(public).map(R::alloc_key)
        }
        #[cfg(feature = "bls")]
        KeyAlg::Bls12_381(BlsCurves::G1G2) => {
            BlsKeyPair::<G1G2>::from_public_bytes(public).map(R::alloc_key)
        }
        #[cfg(feature = "ed25519")]
        KeyAlg::Ed25519 => Ed25519KeyPair::from_public_bytes(public).map(R::alloc_key),
        #[cfg(feature = "ed25519")]
        KeyAlg::X25519 => X25519KeyPair::from_public_bytes(public).map(R::alloc_key),
        #[cfg(feature = "k256")]
        KeyAlg::EcCurve(EcCurves::Secp256k1) => {
            K256KeyPair::from_public_bytes(public).map(R::alloc_key)
        }
        #[cfg(feature = "p256")]
        KeyAlg::EcCurve(EcCurves::Secp256r1) => {
            P256KeyPair::from_public_bytes(public).map(R::alloc_key)
        }
        #[cfg(feature = "p384")]
        KeyAlg::EcCurve(EcCurves::Secp384r1) => {
            P384KeyPair::from_public_bytes(public).map(R::alloc_key)
        }
        #[allow(unreachable_patterns)]
        _ => Err(err_msg!(
            Unsupported,
            "Unsupported algorithm for public key import"
        )),
    }
}

#[inline]
fn from_secret_bytes_any<R: AllocKey>(alg: KeyAlg, secret: &[u8]) -> Result<R, Error> {
    match alg {
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128Gcm) => {
            AesKey::<A128Gcm>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256Gcm) => {
            AesKey::<A256Gcm>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128CbcHs256) => {
            AesKey::<A128CbcHs256>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256CbcHs512) => {
            AesKey::<A256CbcHs512>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128Kw) => {
            AesKey::<A128Kw>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256Kw) => {
            AesKey::<A256Kw>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "bls")]
        KeyAlg::Bls12_381(BlsCurves::G1) => {
            BlsKeyPair::<G1>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "bls")]
        KeyAlg::Bls12_381(BlsCurves::G2) => {
            BlsKeyPair::<G2>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "bls")]
        KeyAlg::Bls12_381(BlsCurves::G1G2) => {
            BlsKeyPair::<G1G2>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "chacha")]
        KeyAlg::Chacha20(Chacha20Types::C20P) => {
            Chacha20Key::<C20P>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "chacha")]
        KeyAlg::Chacha20(Chacha20Types::XC20P) => {
            Chacha20Key::<XC20P>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "ed25519")]
        KeyAlg::Ed25519 => Ed25519KeyPair::from_secret_bytes(secret).map(R::alloc_key),
        #[cfg(feature = "ed25519")]
        KeyAlg::X25519 => X25519KeyPair::from_secret_bytes(secret).map(R::alloc_key),
        #[cfg(feature = "k256")]
        KeyAlg::EcCurve(EcCurves::Secp256k1) => {
            K256KeyPair::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "p256")]
        KeyAlg::EcCurve(EcCurves::Secp256r1) => {
            P256KeyPair::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "p384")]
        KeyAlg::EcCurve(EcCurves::Secp384r1) => {
            P384KeyPair::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[allow(unreachable_patterns)]
        _ => Err(err_msg!(
            Unsupported,
            "Unsupported algorithm for secret key import"
        )),
    }
}

#[cfg(any(feature = "aes", feature = "chacha"))]
#[inline]
fn from_key_exchange_any<R, Sk, Pk>(alg: KeyAlg, secret: &Sk, public: &Pk) -> Result<R, Error>
where
    R: AllocKey,
    Sk: KeyExchange<Pk> + ?Sized,
    Pk: ?Sized,
{
    match alg {
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128Gcm) => {
            AesKey::<A128Gcm>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256Gcm) => {
            AesKey::<A256Gcm>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128CbcHs256) => {
            AesKey::<A128CbcHs256>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256CbcHs512) => {
            AesKey::<A256CbcHs512>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128Kw) => {
            AesKey::<A128Kw>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256Kw) => {
            AesKey::<A256Kw>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        #[cfg(feature = "chacha")]
        KeyAlg::Chacha20(Chacha20Types::C20P) => {
            Chacha20Key::<C20P>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        #[cfg(feature = "chacha")]
        KeyAlg::Chacha20(Chacha20Types::XC20P) => {
            Chacha20Key::<XC20P>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        #[allow(unreachable_patterns)]
        _ => Err(err_msg!(
            Unsupported,
            "Unsupported algorithm for key exchange"
        )),
    }
}

#[cfg(not(any(feature = "aes", feature = "chacha")))]
#[inline]
fn from_key_exchange_any<R, Sk: ?Sized, Pk: ?Sized>(
    _alg: KeyAlg,
    _secret: &Sk,
    _public: &Pk,
) -> Result<R, Error> {
    return Err(err_msg!(
        Unsupported,
        "Unsupported algorithm for key exchange"
    ));
}

#[cfg(any(feature = "aes", feature = "chacha"))]
#[inline]
fn from_key_derivation_any<R: AllocKey>(
    alg: KeyAlg,
    derive: impl KeyDerivation,
) -> Result<R, Error> {
    match alg {
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128Gcm) => {
            AesKey::<A128Gcm>::from_key_derivation(derive).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256Gcm) => {
            AesKey::<A256Gcm>::from_key_derivation(derive).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128CbcHs256) => {
            AesKey::<A128CbcHs256>::from_key_derivation(derive).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256CbcHs512) => {
            AesKey::<A256CbcHs512>::from_key_derivation(derive).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128Kw) => {
            AesKey::<A128Kw>::from_key_derivation(derive).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256Kw) => {
            AesKey::<A256Kw>::from_key_derivation(derive).map(R::alloc_key)
        }
        #[cfg(feature = "chacha")]
        KeyAlg::Chacha20(Chacha20Types::C20P) => {
            Chacha20Key::<C20P>::from_key_derivation(derive).map(R::alloc_key)
        }
        #[cfg(feature = "chacha")]
        KeyAlg::Chacha20(Chacha20Types::XC20P) => {
            Chacha20Key::<XC20P>::from_key_derivation(derive).map(R::alloc_key)
        }
        #[allow(unreachable_patterns)]
        _ => Err(err_msg!(
            Unsupported,
            "Unsupported algorithm for key derivation"
        )),
    }
}

#[cfg(not(any(feature = "aes", feature = "chacha")))]
fn from_key_derivation_any<R: AllocKey>(
    _alg: KeyAlg,
    _derive: impl KeyDerivation,
) -> Result<R, Error> {
    return Err(err_msg!(
        Unsupported,
        "Unsupported algorithm for key derivation"
    ));
}

#[inline]
fn convert_key_any<R: AllocKey>(key: &AnyKey, alg: KeyAlg) -> Result<R, Error> {
    match (key.algorithm(), alg) {
        #[cfg(feature = "bls")]
        (KeyAlg::Bls12_381(BlsCurves::G1G2), KeyAlg::Bls12_381(BlsCurves::G1)) => Ok(R::alloc_key(
            BlsKeyPair::<G1>::from(key.assume::<BlsKeyPair<G1G2>>()),
        )),
        #[cfg(feature = "bls")]
        (KeyAlg::Bls12_381(BlsCurves::G1G2), KeyAlg::Bls12_381(BlsCurves::G2)) => Ok(R::alloc_key(
            BlsKeyPair::<G2>::from(key.assume::<BlsKeyPair<G1G2>>()),
        )),
        #[cfg(feature = "ed25519")]
        (KeyAlg::Ed25519, KeyAlg::X25519) => Ok(<X25519KeyPair as TryFrom<_>>::try_from(
            key.assume::<Ed25519KeyPair>(),
        )
        .map(R::alloc_key)?),
        #[allow(unreachable_patterns)]
        _ => Err(err_msg!(
            Unsupported,
            "Unsupported key conversion operation"
        )),
    }
}

#[inline]
fn get_key_id_any(key: &AnyKey) -> Result<SecretBytes, Error> {
    match key.algorithm() {
        #[cfg(feature = "p256_hardware")]
        KeyAlg::EcCurve(EcCurves::Secp256r1) => {
            Ok(key.assume::<P256HardwareKeyPair>().key_id.clone())
        }
        #[allow(unreachable_patterns)]
        _ => Err(err_msg!(Unsupported, "Unsupported get key id operation")),
    }
}

impl FromJwk for Box<AnyKey> {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        from_jwk_any(jwk)
    }
}

impl FromJwk for Arc<AnyKey> {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        from_jwk_any(jwk)
    }
}

#[inline]
fn from_jwk_any<R: AllocKey>(jwk: JwkParts<'_>) -> Result<R, Error> {
    match (jwk.kty, jwk.crv.as_ref(), jwk.alg.as_ref()) {
        #[cfg(feature = "aes")]
        ("oct", _, A128Gcm::JWK_ALG) => AesKey::<A128Gcm>::from_jwk_parts(jwk).map(R::alloc_key),
        #[cfg(feature = "aes")]
        ("oct", _, A256Gcm::JWK_ALG) => AesKey::<A256Gcm>::from_jwk_parts(jwk).map(R::alloc_key),
        #[cfg(feature = "aes")]
        ("oct", _, A128CbcHs256::JWK_ALG) => {
            AesKey::<A128CbcHs256>::from_jwk_parts(jwk).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        ("oct", _, A256CbcHs512::JWK_ALG) => {
            AesKey::<A256CbcHs512>::from_jwk_parts(jwk).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        ("oct", _, A128Kw::JWK_ALG) => AesKey::<A128Kw>::from_jwk_parts(jwk).map(R::alloc_key),
        #[cfg(feature = "aes")]
        ("oct", _, A256Kw::JWK_ALG) => AesKey::<A256Kw>::from_jwk_parts(jwk).map(R::alloc_key),
        #[cfg(feature = "bls")]
        ("OKP" | "EC", G1::JWK_CURVE, _) => BlsKeyPair::<G1>::from_jwk_parts(jwk).map(R::alloc_key),
        #[cfg(feature = "bls")]
        ("OKP" | "EC", G2::JWK_CURVE, _) => BlsKeyPair::<G2>::from_jwk_parts(jwk).map(R::alloc_key),
        #[cfg(feature = "bls")]
        ("OKP" | "EC", G1G2::JWK_CURVE, _) => {
            BlsKeyPair::<G1G2>::from_jwk_parts(jwk).map(R::alloc_key)
        }
        #[cfg(feature = "chacha")]
        ("oct", _, C20P::JWK_ALG) => Chacha20Key::<C20P>::from_jwk_parts(jwk).map(R::alloc_key),
        #[cfg(feature = "chacha")]
        ("oct", _, XC20P::JWK_ALG) => Chacha20Key::<XC20P>::from_jwk_parts(jwk).map(R::alloc_key),
        #[cfg(feature = "ed25519")]
        ("OKP", ed25519::JWK_CURVE, _) => Ed25519KeyPair::from_jwk_parts(jwk).map(R::alloc_key),
        #[cfg(feature = "ed25519")]
        ("OKP", x25519::JWK_CURVE, _) => X25519KeyPair::from_jwk_parts(jwk).map(R::alloc_key),
        #[cfg(feature = "k256")]
        ("EC", k256::JWK_CURVE, _) => K256KeyPair::from_jwk_parts(jwk).map(R::alloc_key),
        #[cfg(feature = "p256")]
        ("EC", p256::JWK_CURVE, _) => P256KeyPair::from_jwk_parts(jwk).map(R::alloc_key),
        #[cfg(feature = "p384")]
        ("EC", p384::JWK_CURVE, _) => P384KeyPair::from_jwk_parts(jwk).map(R::alloc_key),
        _ => Err(err_msg!(Unsupported, "Unsupported JWK for key import")),
    }
}

macro_rules! match_key_alg {
    ($slf:expr, $ty:ty, $($kty:ident),+ $(,$errmsg:literal)?) => {{
        fn matcher(key: &AnyKey) -> Result<$ty, Error> {
            #[allow(unused_variables)]
            let alg = key.algorithm();
            match_key_alg!(@ $($kty)+ ; key, alg);
            return Err(err_msg!(Unsupported $(,$errmsg)?))
        }
        matcher($slf)
    }};
    (@ ; $key:ident, $alg:ident) => {()};
    (@ Aes $($rest:ident)*; $key:ident, $alg:ident) => {{
        #[cfg(feature = "aes")]
        if $alg == KeyAlg::Aes(AesTypes::A128Gcm) {
            return Ok($key.assume::<AesKey<A128Gcm>>());
        }
        #[cfg(feature = "aes")]
        if $alg == KeyAlg::Aes(AesTypes::A256Gcm) {
            return Ok($key.assume::<AesKey<A256Gcm>>());
        }
        #[cfg(feature = "aes")]
        if $alg == KeyAlg::Aes(AesTypes::A128CbcHs256) {
            return Ok($key.assume::<AesKey<A128CbcHs256>>());
        }
        #[cfg(feature = "aes")]
        if $alg == KeyAlg::Aes(AesTypes::A256CbcHs512) {
            return Ok($key.assume::<AesKey<A256CbcHs512>>());
        }
        #[cfg(feature = "aes")]
        if $alg == KeyAlg::Aes(AesTypes::A128Kw) {
            return Ok($key.assume::<AesKey<A128Kw>>());
        }
        #[cfg(feature = "aes")]
        if $alg == KeyAlg::Aes(AesTypes::A256Kw) {
            return Ok($key.assume::<AesKey<A256Kw>>());
        }
        match_key_alg!(@ $($rest)*; $key, $alg)
    }};
    (@ Bls $($rest:ident)*; $key:ident, $alg:ident) => {{
        #[cfg(feature = "bls")]
        if $alg == KeyAlg::Bls12_381(BlsCurves::G1) {
            return Ok($key.assume::<BlsKeyPair<G1>>());
        }
        #[cfg(feature = "bls")]
        if $alg == KeyAlg::Bls12_381(BlsCurves::G2) {
            return Ok($key.assume::<BlsKeyPair<G2>>());
        }
        #[cfg(feature = "bls")]
        if $alg == KeyAlg::Bls12_381(BlsCurves::G1G2) {
            return Ok($key.assume::<BlsKeyPair<G1G2>>());
        }
        match_key_alg!(@ $($rest)*; $key, $alg)
    }};
    (@ Chacha $($rest:ident)*; $key:ident, $alg:ident) => {{
        #[cfg(feature = "chacha")]
        if $alg == KeyAlg::Chacha20(Chacha20Types::C20P) {
            return Ok($key.assume::<Chacha20Key<C20P>>());
        }
        #[cfg(feature = "chacha")]
        if $alg == KeyAlg::Chacha20(Chacha20Types::XC20P) {
            return Ok($key.assume::<Chacha20Key<XC20P>>());
        }
        match_key_alg!(@ $($rest)*; $key, $alg)
    }};
    (@ Ed25519 $($rest:ident)*; $key:ident, $alg:ident) => {{
        #[cfg(feature = "ed25519")]
        if $alg == KeyAlg::Ed25519 {
            return Ok($key.assume::<Ed25519KeyPair>())
        }
        match_key_alg!(@ $($rest)*; $key, $alg)
    }};
    (@ X25519 $($rest:ident)*; $key:ident, $alg:ident) => {{
        #[cfg(feature = "ed25519")]
        if $alg == KeyAlg::X25519 {
            return Ok($key.assume::<X25519KeyPair>())
        }
        match_key_alg!(@ $($rest)*; $key, $alg)
    }};
    (@ K256 $($rest:ident)*; $key:ident, $alg:ident) => {{
        #[cfg(feature = "k256")]
        if $alg == KeyAlg::EcCurve(EcCurves::Secp256k1) {
            return Ok($key.assume::<K256KeyPair>())
        }
        match_key_alg!(@ $($rest)*; $key, $alg)
    }};
    (@ P256 $($rest:ident)*; $key:ident, $alg:ident) => {{
        #[cfg(feature = "p256")]
        if $alg == KeyAlg::EcCurve(EcCurves::Secp256r1) && $key.backend() == KeyBackend::Software {
            return Ok($key.assume::<P256KeyPair>())
        }
        match_key_alg!(@ $($rest)*; $key, $alg)
    }};
    (@ P256Hardware $($rest:ident)*; $key:ident, $alg:ident) => {{
        #[cfg(feature = "p256_hardware")]
        if $alg == KeyAlg::EcCurve(EcCurves::Secp256r1) && $key.backend() == KeyBackend::SecureElement {
            return Ok($key.assume::<P256HardwareKeyPair>())
        }
        match_key_alg!(@ $($rest)*; $key, $alg)
    }};
    (@ P384 $($rest:ident)*; $key:ident, $alg:ident) => {{
        #[cfg(feature = "p384")]
        if $alg == KeyAlg::EcCurve(EcCurves::Secp384r1) {
            return Ok($key.assume::<P384KeyPair>())
        }
        match_key_alg!(@ $($rest)*; $key, $alg)
    }};
}

impl AnyKey {
    fn key_as_aead(&self) -> Result<&dyn KeyAeadInPlace, Error> {
        match_key_alg! {
            self,
            &dyn KeyAeadInPlace,
            Aes,
            Chacha,
            "AEAD is not supported for this key type"
        }
    }

    fn key_to_secret(&self) -> Result<&dyn ToSecretBytes, Error> {
        match_key_alg! {
            self,
            &dyn ToSecretBytes,
            Aes,
            Bls,
            Chacha,
            Ed25519,
            K256,
            P256,
            P384,
            X25519,
            "Secret key export is not supported for this key type"
        }
    }

    fn key_to_public(&self) -> Result<&dyn ToPublicBytes, Error> {
        match_key_alg! {
            self,
            &dyn ToPublicBytes,
            Bls,
            Ed25519,
            K256,
            P256,
            P256Hardware,
            P384,
            X25519,
            "Public key export is not supported for this key type"
        }
    }
}

impl ToPublicBytes for AnyKey {
    fn public_bytes_length(&self) -> Result<usize, Error> {
        self.key_to_public()?.public_bytes_length()
    }

    fn write_public_bytes(&self, out: &mut dyn WriteBuffer) -> Result<(), Error> {
        self.key_to_public()?.write_public_bytes(out)
    }
}

impl ToSecretBytes for AnyKey {
    fn secret_bytes_length(&self) -> Result<usize, Error> {
        self.key_to_secret()?.secret_bytes_length()
    }

    fn write_secret_bytes(&self, out: &mut dyn WriteBuffer) -> Result<(), Error> {
        self.key_to_secret()?.write_secret_bytes(out)
    }
}

impl KeyExchange for AnyKey {
    fn write_key_exchange(&self, other: &AnyKey, out: &mut dyn WriteBuffer) -> Result<(), Error> {
        if self.key_type_id() != other.key_type_id() {
            return Err(err_msg!(Unsupported, "Unsupported key exchange"));
        }
        match self.algorithm() {
            #[cfg(feature = "ed25519")]
            KeyAlg::X25519 => Ok(self
                .assume::<X25519KeyPair>()
                .write_key_exchange(other.assume::<X25519KeyPair>(), out)?),
            #[cfg(feature = "k256")]
            KeyAlg::EcCurve(EcCurves::Secp256k1) => Ok(self
                .assume::<K256KeyPair>()
                .write_key_exchange(other.assume::<K256KeyPair>(), out)?),
            #[cfg(feature = "p256")]
            KeyAlg::EcCurve(EcCurves::Secp256r1) => Ok(self
                .assume::<P256KeyPair>()
                .write_key_exchange(other.assume::<P256KeyPair>(), out)?),
            #[cfg(feature = "p384")]
            KeyAlg::EcCurve(EcCurves::Secp384r1) => Ok(self
                .assume::<P384KeyPair>()
                .write_key_exchange(other.assume::<P384KeyPair>(), out)?),
            #[allow(unreachable_patterns)]
            _ => {
                let _ = out;
                Err(err_msg!(Unsupported, "Unsupported key exchange"))
            }
        }
    }
}

impl KeyAeadInPlace for AnyKey {
    fn encrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<usize, Error> {
        self.key_as_aead()?.encrypt_in_place(buffer, nonce, aad)
    }

    fn decrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error> {
        self.key_as_aead()?.decrypt_in_place(buffer, nonce, aad)
    }

    fn aead_params(&self) -> KeyAeadParams {
        if let Ok(key) = self.key_as_aead() {
            key.aead_params()
        } else {
            KeyAeadParams::default()
        }
    }

    fn aead_padding(&self, msg_len: usize) -> usize {
        if let Ok(key) = self.key_as_aead() {
            key.aead_padding(msg_len)
        } else {
            0
        }
    }
}

impl ToJwk for AnyKey {
    fn encode_jwk(&self, enc: &mut dyn JwkEncoder) -> Result<(), Error> {
        let key = match_key_alg! {
            self,
            &dyn ToJwk,
            Aes,
            Bls,
            Chacha,
            Ed25519,
            K256,
            P256,
            P256Hardware,
            P384,
            X25519,
            "JWK export is not supported for this key type"
        }?;
        key.encode_jwk(enc)
    }
}

impl KeySign for AnyKey {
    fn write_signature(
        &self,
        message: &[u8],
        sig_type: Option<SignatureType>,
        out: &mut dyn WriteBuffer,
    ) -> Result<(), Error> {
        let key = match_key_alg! {
            self,
            &dyn KeySign,
            Ed25519,
            K256,
            P256,
            P256Hardware,
            P384,
            "Signing is not supported for this key type"
        }?;
        key.write_signature(message, sig_type, out)
    }
}

impl KeySigVerify for AnyKey {
    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<bool, Error> {
        let key = match_key_alg! {
            self,
            &dyn KeySigVerify,
            Ed25519,
            K256,
            P256,
            P256Hardware,
            P384,
            "Signature verification is not supported for this key type"
        }?;
        key.verify_signature(message, signature, sig_type)
    }
}

// may want to implement in-place initialization to avoid copies
trait AllocKey {
    fn alloc_key<K: AnyKeyAlg + Send + Sync + RefUnwindSafe + UnwindSafe>(key: K) -> Self;
}

impl AllocKey for Arc<AnyKey> {
    #[inline(always)]
    fn alloc_key<K: AnyKeyAlg + Send + Sync + RefUnwindSafe + UnwindSafe>(key: K) -> Self {
        Self::from_key(key)
    }
}

impl AllocKey for Box<AnyKey> {
    #[inline(always)]
    fn alloc_key<K: AnyKeyAlg + Send + Sync + RefUnwindSafe + UnwindSafe>(key: K) -> Self {
        Self::from_key(key)
    }
}

pub trait AnyKeyAlg: HasKeyAlg + HasKeyBackend + 'static {
    fn as_any(&self) -> &dyn Any;
}

// implement for all concrete key types
impl<K: HasKeyAlg + HasKeyBackend + Sized + 'static> AnyKeyAlg for K {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    // FIXME - add a custom key type for testing, to allow feature independence

    #[cfg(feature = "ed25519")]
    #[test]
    fn ed25519_as_any() {
        let key = Box::<AnyKey>::random(KeyAlg::Ed25519).unwrap();
        assert_eq!(key.algorithm(), KeyAlg::Ed25519);
        assert_eq!(key.key_type_id(), TypeId::of::<Ed25519KeyPair>());
        let _ = key.to_jwk_public(None).unwrap();
    }

    #[cfg(feature = "aes")]
    #[test]
    fn key_exchange_any() {
        let alice = Box::<AnyKey>::random(KeyAlg::X25519).unwrap();
        let bob = Box::<AnyKey>::random(KeyAlg::X25519).unwrap();
        let exch_a = alice.key_exchange_bytes(&bob).unwrap();
        let exch_b = bob.key_exchange_bytes(&alice).unwrap();
        assert_eq!(exch_a, exch_b);

        let _aes_key =
            Box::<AnyKey>::from_key_exchange(KeyAlg::Aes(AesTypes::A256Gcm), &*alice, &*bob)
                .unwrap();
    }

    #[cfg(feature = "chacha")]
    #[test]
    fn key_encrypt_any() {
        use crate::buffer::SecretBytes;
        let message = b"test message";
        let mut data = SecretBytes::from(&message[..]);

        let key = Box::<AnyKey>::random(KeyAlg::Chacha20(Chacha20Types::XC20P)).unwrap();
        let nonce = [0u8; 24]; // size varies by algorithm
        key.encrypt_in_place(&mut data, &nonce, &[]).unwrap();
        assert_ne!(data, &message[..]);
        key.decrypt_in_place(&mut data, &nonce, &[]).unwrap();
        assert_eq!(data, &message[..]);
    }
}
