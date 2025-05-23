//! BLS12-381 key support

use core::{
    fmt::{self, Debug, Formatter},
    ops::Add,
};

use aead::generic_array::GenericArray;
use blake2::Digest;
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::generic_array::{
    typenum::{self, Unsigned, U192, U32, U48, U96},
    ArrayLength,
};

use super::{BlsCurves, HasKeyAlg, HasKeyBackend, KeyAlg};
use crate::{
    buffer::ArrayKey,
    error::Error,
    jwk::{FromJwk, JwkEncoder, JwkParts, ToJwk},
    random::KeyMaterial,
    repr::{KeyGen, KeyMeta, KeyPublicBytes, KeySecretBytes, KeypairMeta},
};

/// The 'kty' value of a BLS key JWK
pub const JWK_KEY_TYPE_EC: &str = "EC";
/// The 'kty' value of a BLS key JWK (OKP variant)
pub const JWK_KEY_TYPE_OKP: &str = "OKP";

/// A BLS12-381 key pair
#[derive(Clone, Zeroize)]
pub struct BlsKeyPair<Pk: BlsPublicKeyType> {
    secret: Option<BlsSecretKey>,
    public: Pk::Buffer,
}

impl<Pk: BlsPublicKeyType> BlsKeyPair<Pk> {
    /// Generate a new BLS key from a seed according to the KeyGen algorithm
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_secret_key(BlsSecretKey::generate(
            BlsKeyGen::new(seed)?,
        )?))
    }

    #[inline]
    pub(crate) fn from_secret_key(sk: BlsSecretKey) -> Self {
        let public = Pk::from_secret_scalar(&sk.0);
        Self {
            secret: Some(sk),
            public,
        }
    }

    /// Accessor for the associated public key
    pub fn bls_public_key(&self) -> &Pk::Buffer {
        &self.public
    }

    /// Accessor for the associated secret key value, if any
    pub fn bls_secret_scalar(&self) -> Option<&Scalar> {
        self.secret.as_ref().map(|s| &s.0)
    }
}

impl<Pk: BlsPublicKeyType> Debug for BlsKeyPair<Pk> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlsKeyPair")
            .field("crv", &Pk::JWK_CURVE)
            .field("secret", &self.secret)
            .field("public", &self.public)
            .finish()
    }
}

impl<Pk: BlsPublicKeyType> PartialEq for BlsKeyPair<Pk> {
    fn eq(&self, other: &Self) -> bool {
        other.secret == self.secret && other.public == self.public
    }
}

impl<Pk: BlsPublicKeyType> Eq for BlsKeyPair<Pk> {}

impl<Pk: BlsPublicKeyType> HasKeyBackend for BlsKeyPair<Pk> {}

impl<Pk: BlsPublicKeyType> HasKeyAlg for BlsKeyPair<Pk> {
    fn algorithm(&self) -> KeyAlg {
        KeyAlg::Bls12_381(Pk::ALG_TYPE)
    }
}

impl<Pk: BlsPublicKeyType> KeyMeta for BlsKeyPair<Pk> {
    type KeySize = U32;
}

impl<Pk> KeypairMeta for BlsKeyPair<Pk>
where
    Pk: BlsPublicKeyType,
    U32: Add<Pk::BufferSize>,
    <U32 as Add<Pk::BufferSize>>::Output: ArrayLength<u8>,
{
    type PublicKeySize = Pk::BufferSize;
    type KeypairSize = typenum::Sum<Self::KeySize, Pk::BufferSize>;
}

impl<Pk: BlsPublicKeyType> KeyGen for BlsKeyPair<Pk> {
    fn generate(rng: impl KeyMaterial) -> Result<Self, Error> {
        let secret = BlsSecretKey::generate(rng)?;
        Ok(Self::from_secret_key(secret))
    }
}

impl<Pk: BlsPublicKeyType> KeySecretBytes for BlsKeyPair<Pk> {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let sk = BlsSecretKey::from_bytes(key)?;
        Ok(Self::from_secret_key(sk))
    }

    fn with_secret_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        if let Some(sk) = self.secret.as_ref() {
            let mut skb = Zeroizing::new(sk.0.to_bytes());
            skb.reverse(); // into big-endian
            f(Some(&*skb))
        } else {
            f(None)
        }
    }
}

impl<Pk: BlsPublicKeyType> KeyPublicBytes for BlsKeyPair<Pk>
where
    Self: KeypairMeta,
{
    fn from_public_bytes(key: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            secret: None,
            public: Pk::from_public_bytes(key)?,
        })
    }

    fn with_public_bytes<O>(&self, f: impl FnOnce(&[u8]) -> O) -> O {
        Pk::with_bytes(&self.public, None, f)
    }
}

impl<Pk: BlsPublicKeyType> ToJwk for BlsKeyPair<Pk> {
    fn encode_jwk(&self, enc: &mut dyn JwkEncoder) -> Result<(), Error> {
        enc.add_str("crv", Pk::get_jwk_curve(enc.alg()))?;
        enc.add_str("kty", JWK_KEY_TYPE_EC)?;
        Pk::with_bytes_uncompressed(&self.public, enc.alg(), |buf| {
            enc.add_as_base64("x", &buf[..Pk::BufferSize::USIZE])?;
            enc.add_as_base64("y", &buf[Pk::BufferSize::USIZE..])
        })?;
        if enc.is_secret() {
            self.with_secret_bytes(|buf| {
                if let Some(sk) = buf {
                    let mut skr = Zeroizing::new([0u8; 32]);
                    skr.copy_from_slice(sk);
                    skr.reverse(); // into little-endian
                    enc.add_as_base64("d", skr.as_ref())
                } else {
                    Ok(())
                }
            })?;
        }
        Ok(())
    }
}

impl<Pk: BlsPublicKeyType> FromJwk for BlsKeyPair<Pk> {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        let public = match jwk.kty {
            JWK_KEY_TYPE_EC => {
                if jwk.crv != Pk::JWK_CURVE {
                    return Err(err_msg!(InvalidKeyData, "Unsupported key algorithm"));
                }

                ArrayKey::<Pk::BufferSizeWide>::temp(|arr| {
                    // decode the x and y coordinates, individual lengths may be less than the full size
                    jwk.x.decode_base64(&mut arr[..Pk::BufferSize::USIZE])?;
                    jwk.y.decode_base64(&mut arr[Pk::BufferSize::USIZE..])?;
                    Pk::from_public_bytes(arr)
                })
                .map_err(|_| err_msg!(InvalidKeyData, "Invalid public key coordinates"))?
            }

            // for compatibility with previous version
            JWK_KEY_TYPE_OKP => {
                if jwk.crv != Pk::JWK_CURVE_OKP {
                    return Err(err_msg!(InvalidKeyData, "Unsupported key algorithm"));
                }
                if jwk.y.is_some() {
                    return Err(err_msg!(InvalidKeyData, "Disallowed y coordinate"));
                }

                ArrayKey::<Pk::BufferSize>::temp(|arr| {
                    jwk.x.decode_base64(arr)?;
                    Pk::from_public_bytes(arr)
                })
                .map_err(|_| err_msg!(InvalidKeyData, "Invalid public key coordinates"))?
            }

            _ => {
                return Err(err_msg!(InvalidKeyData, "Unsupported key type"));
            }
        };

        if jwk.d.is_some() {
            ArrayKey::<U32>::temp(|sk_arr| {
                if jwk.d.decode_base64(sk_arr)? != sk_arr.len() {
                    Err(err_msg!(InvalidKeyData, "Invalid private key"))
                } else {
                    if jwk.kty == JWK_KEY_TYPE_EC {
                        sk_arr.reverse(); // into big-endian
                    }
                    let result = BlsKeyPair::from_secret_key(BlsSecretKey::from_bytes(sk_arr)?);
                    if result.public != public {
                        return Err(err_msg!(InvalidKeyData, "Public key mismatch"));
                    }
                    Ok(result)
                }
            })
        } else {
            Ok(Self {
                secret: None,
                public,
            })
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
#[repr(transparent)]
pub(crate) struct BlsSecretKey(Scalar);

impl BlsSecretKey {
    fn generate(mut rng: impl KeyMaterial) -> Result<Self, Error> {
        let mut secret = Zeroizing::new([0u8; 64]);
        rng.read_okm(&mut secret[16..]);
        secret.reverse(); // into little endian
        Ok(Self(Scalar::from_bytes_wide(&secret)))
    }

    pub fn from_bytes(sk: &[u8]) -> Result<Self, Error> {
        if sk.len() != 32 {
            return Err(err_msg!(InvalidKeyData));
        }
        let mut skb = Zeroizing::new([0u8; 32]);
        skb.copy_from_slice(sk);
        skb.reverse(); // into little endian
        let result: Option<Scalar> = Scalar::from_bytes(&skb).into();
        Ok(Self(result.ok_or_else(|| err_msg!(InvalidKeyData))?))
    }
}

impl Drop for BlsSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A key material generator compatible with KeyGen from the
/// bls-signatures RFC draft 4 (incompatible with earlier)
#[derive(Debug, Clone)]
pub struct BlsKeyGen<'g> {
    salt: Option<GenericArray<u8, U32>>,
    ikm: &'g [u8],
}

impl<'g> BlsKeyGen<'g> {
    /// Construct a new `BlsKeyGen` from a seed value
    pub fn new(ikm: &'g [u8]) -> Result<Self, Error> {
        if ikm.len() < 32 {
            return Err(err_msg!(Usage, "Insufficient length for seed"));
        }
        Ok(Self { salt: None, ikm })
    }
}

impl KeyMaterial for BlsKeyGen<'_> {
    fn read_okm(&mut self, buf: &mut [u8]) {
        const SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";

        self.salt.replace(match self.salt {
            None => Sha256::digest(SALT),
            Some(salt) => Sha256::digest(salt),
        });
        let mut extract = hkdf::HkdfExtract::<Sha256>::new(Some(self.salt.as_ref().unwrap()));
        extract.input_ikm(self.ikm);
        extract.input_ikm(&[0u8]);
        let (_, hkdf) = extract.finalize();
        hkdf.expand(&(buf.len() as u16).to_be_bytes(), buf)
            .expect("HDKF extract failure");
    }
}

/// Trait implemented by supported BLS public key types
pub trait BlsPublicKeyType: 'static {
    /// The concrete key representation
    type Buffer: Clone + Debug + PartialEq + Sized + Zeroize;

    /// The size of the serialized compressed public key
    type BufferSize: ArrayLength<u8>;
    /// The size of the serialized uncompressed public key
    type BufferSizeWide: ArrayLength<u8>;

    /// The associated algorithm type
    const ALG_TYPE: BlsCurves;
    /// The associated JWK curve name
    const JWK_CURVE: &'static str;
    /// The associated JWK curve name (OKP variant)
    const JWK_CURVE_OKP: &'static str;

    /// Get the JWK curve for a specific key algorithm
    fn get_jwk_curve(_alg: Option<KeyAlg>) -> &'static str {
        Self::JWK_CURVE
    }

    /// Initialize from the secret scalar
    fn from_secret_scalar(secret: &Scalar) -> Self::Buffer;

    /// Initialize from the compressed bytes
    fn from_public_bytes(key: &[u8]) -> Result<Self::Buffer, Error>;

    /// Access the bytes of the public key
    fn with_bytes<O>(buf: &Self::Buffer, alg: Option<KeyAlg>, f: impl FnOnce(&[u8]) -> O) -> O;

    /// Access the coordinates of the public key
    fn with_bytes_uncompressed<O>(
        buf: &Self::Buffer,
        alg: Option<KeyAlg>,
        f: impl FnOnce(&[u8]) -> O,
    ) -> O;
}

/// G1 curve
#[derive(Debug)]
pub struct G1;

impl BlsPublicKeyType for G1 {
    type Buffer = G1Affine;
    type BufferSize = U48;
    type BufferSizeWide = U96;

    const ALG_TYPE: BlsCurves = BlsCurves::G1;
    const JWK_CURVE: &'static str = "BLS12381G1";
    const JWK_CURVE_OKP: &'static str = "BLS12381_G1";

    #[inline]
    fn from_secret_scalar(secret: &Scalar) -> Self::Buffer {
        G1Affine::from(G1Projective::generator() * secret)
    }

    fn from_public_bytes(key: &[u8]) -> Result<Self::Buffer, Error> {
        let res = if let Ok(buf) = key.try_into() {
            G1Affine::from_compressed(buf).into_option()
        } else if let Ok(buf) = key.try_into() {
            G1Affine::from_uncompressed(buf).into_option()
        } else {
            None
        };
        res.ok_or_else(|| err_msg!(InvalidKeyData))
    }

    fn with_bytes<O>(buf: &Self::Buffer, _alg: Option<KeyAlg>, f: impl FnOnce(&[u8]) -> O) -> O {
        f(buf.to_compressed().as_ref())
    }

    fn with_bytes_uncompressed<O>(
        buf: &Self::Buffer,
        _alg: Option<KeyAlg>,
        f: impl FnOnce(&[u8]) -> O,
    ) -> O {
        f(buf.to_uncompressed().as_ref())
    }
}

/// G2 curve
#[derive(Debug)]
pub struct G2;

impl BlsPublicKeyType for G2 {
    type Buffer = G2Affine;
    type BufferSize = U96;
    type BufferSizeWide = U192;

    const ALG_TYPE: BlsCurves = BlsCurves::G2;
    const JWK_CURVE: &'static str = "BLS12381G2";
    const JWK_CURVE_OKP: &'static str = "BLS12381_G2";

    #[inline]
    fn from_secret_scalar(secret: &Scalar) -> Self::Buffer {
        G2Affine::from(G2Projective::generator() * secret)
    }

    fn from_public_bytes(key: &[u8]) -> Result<Self::Buffer, Error> {
        let res = if let Ok(buf) = key.try_into() {
            G2Affine::from_compressed(buf).into_option()
        } else if let Ok(buf) = key.try_into() {
            G2Affine::from_uncompressed(buf).into_option()
        } else {
            None
        };
        res.ok_or_else(|| err_msg!(InvalidKeyData))
    }

    fn with_bytes<O>(buf: &Self::Buffer, _alg: Option<KeyAlg>, f: impl FnOnce(&[u8]) -> O) -> O {
        f(buf.to_compressed().as_ref())
    }

    fn with_bytes_uncompressed<O>(
        buf: &Self::Buffer,
        _alg: Option<KeyAlg>,
        f: impl FnOnce(&[u8]) -> O,
    ) -> O {
        f(buf.to_uncompressed().as_ref())
    }
}

impl TryFrom<&BlsKeyPair<G1>> for BlsKeyPair<G2> {
    type Error = Error;

    fn try_from(kp: &BlsKeyPair<G1>) -> Result<Self, Self::Error> {
        if let Some(sec) = kp.secret.as_ref() {
            Ok(BlsKeyPair {
                secret: Some(sec.clone()),
                public: G2::from_secret_scalar(&sec.0),
            })
        } else {
            Err(err_msg!(InvalidKeyData, "No secret key available"))
        }
    }
}

impl TryFrom<&BlsKeyPair<G2>> for BlsKeyPair<G1> {
    type Error = Error;

    fn try_from(kp: &BlsKeyPair<G2>) -> Result<Self, Self::Error> {
        if let Some(sec) = kp.secret.as_ref() {
            Ok(BlsKeyPair {
                secret: Some(sec.clone()),
                public: G1::from_secret_scalar(&sec.0),
            })
        } else {
            Err(err_msg!(InvalidKeyData, "No secret key available"))
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use std::string::ToString;

    use super::*;
    use crate::repr::{ToPublicBytes, ToSecretBytes};

    // test against EIP-2333 (as updated for signatures draft 4)
    #[test]
    fn key_gen_expected() {
        let seed = &hex!(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553
            1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
        let kp = BlsKeyPair::<G1>::from_seed(&seed[..]).unwrap();
        let sk = kp.to_secret_bytes().unwrap();
        assert_eq!(
            sk.as_hex().to_string(),
            "0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070"
        );
    }

    #[test]
    fn g1_key_expected() {
        let sk = hex!("0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070");
        let kp = BlsKeyPair::<G1>::from_secret_bytes(&sk[..]).unwrap();
        let pk = kp.to_public_bytes().unwrap();
        assert_eq!(
            pk.as_hex().to_string(),
            "a2c975348667926acf12f3eecb005044e08a7a9b7d95f30bd281b55445107367a2e5d0558be7943c8bd13f9a1a7036fb"
        );
        assert_eq!(
            BlsKeyPair::<G1>::from_public_bytes(pk.as_ref())
                .unwrap()
                .to_public_bytes()
                .unwrap(),
            pk
        );
    }

    #[test]
    fn g2_key_expected() {
        let sk = hex!("0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070");
        let kp = BlsKeyPair::<G2>::from_secret_bytes(&sk[..]).unwrap();
        let pk = kp.to_public_bytes().unwrap();
        assert_eq!(
            pk.as_hex().to_string(),
            "a5e43d5ecb7b8c01ceb3b91f7413b628ef02c6859dc42a4354b21f9195531988a648655037faafd1bac2fd2d7d9466180baa3705a45a6c597853db51eaf431616057fd8049c6bee8764292f9a104200a45a63ceae9d3c368643ab9e5ff0f8810"
        );
        assert_eq!(
            BlsKeyPair::<G2>::from_public_bytes(pk.as_ref())
                .unwrap()
                .to_public_bytes()
                .unwrap(),
            pk
        );
    }

    #[test]
    fn g1_jwk_expected() {
        let test_pvt = &hex!("0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070");
        let test_pub_g1_x = &hex!("02c975348667926acf12f3eecb005044e08a7a9b7d95f30bd281b55445107367a2e5d0558be7943c8bd13f9a1a7036fb");
        let test_pub_g1_y = &hex!("13f396ec1b79d6f461189d20a0d3f27718dd6efff3066c31380d785bce9957abc640d2f1301266d1e9d7b1e6da60da95");
        let kp = BlsKeyPair::<G1>::from_secret_bytes(&test_pvt[..]).expect("Error creating key");

        let jwk = kp.to_jwk_public(None).expect("Error converting key to JWK");
        let jwk = JwkParts::try_from_str(&jwk).expect("Error parsing JWK");
        assert_eq!(jwk.kty, JWK_KEY_TYPE_EC);
        assert_eq!(jwk.crv, G1::JWK_CURVE);
        assert_eq!(
            jwk.x,
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(test_pub_g1_x)
                .as_str()
        );
        assert_eq!(
            jwk.y,
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(test_pub_g1_y)
                .as_str()
        );
        assert_eq!(jwk.d, None);
        let pk_load = BlsKeyPair::<G1>::from_jwk_parts(jwk).unwrap();
        assert_eq!(kp.to_public_bytes(), pk_load.to_public_bytes());

        let jwk = kp.to_jwk_secret(None).expect("Error converting key to JWK");
        let jwk = JwkParts::from_slice(&jwk).expect("Error parsing JWK");
        assert_eq!(jwk.kty, JWK_KEY_TYPE_EC);
        assert_eq!(jwk.crv, G1::JWK_CURVE);
        assert_eq!(
            jwk.x,
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(test_pub_g1_x)
                .as_str()
        );
        assert_eq!(
            jwk.y,
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(test_pub_g1_y)
                .as_str()
        );
        let mut sk_rev = *test_pvt;
        sk_rev.reverse(); // into little-endian
        assert_eq!(
            jwk.d,
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sk_rev)
                .as_str()
        );
        let _sk_load = BlsKeyPair::<G1>::from_jwk_parts(jwk).unwrap();
        // assert_eq!(
        //     kp.to_keypair_bytes().unwrap(),
        //     sk_load.to_keypair_bytes().unwrap()
        // );
    }

    #[cfg(feature = "any_key")]
    #[test]
    // test loading of a key with the EC key type along with conversion to a G2 key
    fn g1_jwk_any() {
        use crate::alg::{any::AnyKey, AnyKeyCreate, BlsCurves, KeyAlg};
        use alloc::boxed::Box;

        let test_jwk = r#"
            {
                "kty": "EC",
                "crv": "BLS12381G1",
                "x": "Ed4GBGLVasEp4ejPz44CvllbTldfLLcm2QcIJluBL6p_SQmRrZvJNa3YaJ-Wx8Im",
                "y": "AbdYAsAb20CHzlVW6VBO9i16BcGOmcYiMLlBEh9DfAiDu_1ZIAd1zewSi9f6517g",
                "d": "3nc6_s38FVVlawbwmPFOjB4TlAPy_K2Tx39I7XnEnDc"
            }
        "#;
        let test_jwk_g2 = r#"
            {
                "kty": "EC",
                "crv": "BLS12381G2",
                "x": "GJ4CTKTdbhJ606E_zoXvBerW3susF0rCRkkOjSSoXzAbo75pF5a_TuUGrYICNRpKA6cQe4FqWEgLW0KKW3-5nAXX1BEKk2flns1VE-2hpbRZqmfA0xPyLPomtUBmLZsR",
                "y": "AnUhMCJ0P0MITDiU4Xf_NHGiJZoyVXGol99Xrrn4fqAcQ-SIXTgbIEP3aBHvsaiQCKqnpWzWycJ4AYOVcaDgKs-ms5bweXiDAafBO-tiuCcrqeAJzY_ZJtNon8IvP_5-",
                "d": "3nc6_s38FVVlawbwmPFOjB4TlAPy_K2Tx39I7XnEnDc"
            }
        "#;
        let key = Box::<AnyKey>::from_jwk(test_jwk).expect("Error decoding BLS key JWK");
        assert_eq!(key.algorithm(), KeyAlg::Bls12_381(BlsCurves::G1));
        let as_g1 = key
            .downcast_ref::<BlsKeyPair<G1>>()
            .expect("Error downcasting BLS key");
        let _ = as_g1
            .to_jwk_public(None)
            .expect("Error converting key to JWK");
        let g2key = key
            .convert_key(KeyAlg::Bls12_381(BlsCurves::G2))
            .expect("Error converting keypair");
        assert_eq!(g2key.algorithm(), KeyAlg::Bls12_381(BlsCurves::G2));
        let as_g2 = g2key
            .downcast_ref::<BlsKeyPair<G2>>()
            .expect("Error downcasting BLS key");
        let g2_expect =
            BlsKeyPair::<G2>::from_jwk(test_jwk_g2).expect("Error decoding BLS key JWK");
        assert_eq!(&g2_expect, as_g2);
    }

    #[cfg(feature = "any_key")]
    #[test]
    // test loading of a key with the OKP key type
    fn g1_jwk_any_compat() {
        use crate::alg::{any::AnyKey, BlsCurves, KeyAlg};
        use alloc::boxed::Box;

        let test_jwk_compat = r#"
            {
                "crv":"BLS12381_G1",
                "kty":"OKP",
                "x":"lQ-SOS1aBydOBEHaKThf667LGeZVe3EiVSLXRd8Y3DBuR8ll4VJONAlytjG1CAc7",
                "d":"XMltkZ-3H94Rl8orHfWufxrPe1hdURFAUKdyt0SNdrk"
            }
        "#;
        let test_jwk_new = r#"
            {
                "crv":"BLS12381G1",
                "kty":"EC",
                "x":"FQ-SOS1aBydOBEHaKThf667LGeZVe3EiVSLXRd8Y3DBuR8ll4VJONAlytjG1CAc7",
                "y":"CvFVTlp_IO8NxTIekI8Ik9drVLNUCQl6sfo6zDa7oOiaoxqTfTnU70HLJzjHQ6_m",
                "d":"uXaNRLdyp1BAEVFdWHvPGn-u9R0rypcR3h-3n5FtyVw"
            }
        "#;
        let key = Box::<AnyKey>::from_jwk(test_jwk_compat).expect("Error decoding BLS key JWK");
        assert_eq!(key.algorithm(), KeyAlg::Bls12_381(BlsCurves::G1));
        let as_bls = key
            .downcast_ref::<BlsKeyPair<G1>>()
            .expect("Error downcasting BLS key");

        let knew = BlsKeyPair::<G1>::from_jwk(test_jwk_new).expect("Error decoding BLS key JWK");
        assert_eq!(as_bls, &knew);

        let _ = as_bls
            .to_jwk_public(None)
            .expect("Error converting key to JWK");
    }
}
