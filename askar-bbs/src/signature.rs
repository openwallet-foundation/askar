use core::convert::TryInto;

use askar_crypto::alg::bls::{BlsKeyPair, G2};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use group::Curve;
use subtle::ConstantTimeEq;

use crate::{
    commitment::{Blinding, Commitment},
    generators::Generators,
    hash::HashScalar,
    io::FixedLengthBytes,
    util::AccumG1,
    Error,
};

const SIGNATURE_LENGTH: usize = 48 + 32 + 32;

impl_scalar_type!(Message, "A message value used in a signature");

impl Message {
    /// Generate a message value by hashing arbitrary length input
    pub fn hash(input: impl AsRef<[u8]>) -> Self {
        Self(HashScalar::digest(input, None))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// A BBS+ signature value
pub struct Signature {
    pub(crate) a: G1Affine,
    pub(crate) e: Scalar,
    pub(crate) s: Scalar,
}

impl Signature {
    /// Unblind a signature created against a commitment
    pub fn unblind(self, blinding: Blinding) -> Self {
        let Signature { a, e, s } = self;
        Self {
            a,
            e,
            s: s + blinding.0,
        }
    }
}

impl FixedLengthBytes for Signature {
    const LENGTH: usize = SIGNATURE_LENGTH;

    type Buffer = [u8; SIGNATURE_LENGTH];

    fn with_bytes<R>(&self, f: impl FnOnce(&Self::Buffer) -> R) -> R {
        let mut buf = [0u8; Self::LENGTH];
        buf[..48].copy_from_slice(&self.a.to_compressed()[..]);
        buf[48..80].copy_from_slice(&self.e.to_bytes()[..]);
        buf[48..80].reverse(); // into big endian
        buf[80..].copy_from_slice(&self.s.to_bytes()[..]);
        buf[80..].reverse(); // into big endian
        f(&buf)
    }

    fn from_bytes(sig: &Self::Buffer) -> Result<Self, Error> {
        let buf = sig.as_ref();
        let a = G1Affine::from_compressed(&buf[..48].try_into().unwrap());
        let mut scalar: [u8; 32] = buf[48..80].try_into().unwrap();
        scalar.reverse(); // from big endian
        let e = Scalar::from_bytes(&scalar);
        scalar.copy_from_slice(&buf[80..]);
        scalar.reverse(); // from big endian
        let s = Scalar::from_bytes(&scalar);
        if let (Some(a), Some(e), Some(s)) = (a.into(), e.into(), s.into()) {
            Ok(Self { a, e, s })
        } else {
            Err(err_msg!(Invalid))
        }
    }
}

#[derive(Clone, Debug)]
/// A builder for a signature
pub struct SignatureBuilder<'g, G: Generators> {
    accum_b: AccumG1,
    generators: &'g G,
    hash_es: HashScalar<'static>,
    key: &'g BlsKeyPair<G2>,
    message_count: usize,
}

impl<'g, G: Generators> SignatureBuilder<'g, G> {
    /// Create a new signature builder
    pub fn new(generators: &'g G, key: &'g BlsKeyPair<G2>) -> Self {
        Self::from_accum(generators, key, G1Projective::generator())
    }

    /// Create a new signature builder with a blinded messages commitment value
    pub fn from_commitment(
        generators: &'g G,
        key: &'g BlsKeyPair<G2>,
        commitment: Commitment,
    ) -> Self {
        Self::from_accum(generators, key, G1Projective::generator() + commitment.0)
    }

    #[inline]
    fn from_accum(generators: &'g G, key: &'g BlsKeyPair<G2>, sum: G1Projective) -> Self {
        Self {
            accum_b: AccumG1::new_with(sum),
            generators,
            hash_es: HashScalar::new_with_input(&sum.to_affine().to_compressed(), None),
            key,
            message_count: 0,
        }
    }
}

impl<G: Generators> SignatureBuilder<'_, G> {
    /// Push a message to be signed
    pub fn push_message(&mut self, message: Message) -> Result<(), Error> {
        let c = self.message_count;
        if c >= self.generators.message_count() {
            return Err(err_msg!(Usage, "Message index exceeds generator count"));
        }
        self.accum_b.push(self.generators.message(c), message.0);
        self.hash_es.update(&message.0.to_bytes());
        self.message_count = c + 1;
        Ok(())
    }

    /// Push a sequence of messages to be signed
    pub fn append_messages(
        &mut self,
        messages: impl IntoIterator<Item = Message>,
    ) -> Result<(), Error> {
        for msg in messages {
            self.push_message(msg)?;
        }
        Ok(())
    }

    /// Push a number of blind (committed) messages
    pub fn push_committed_count(&mut self, count: usize) -> Result<(), Error> {
        let c = self.message_count + count;
        if c > self.generators.message_count() {
            return Err(err_msg!(Usage, "Message index exceeds generator count"));
        }
        self.message_count = c;
        Ok(())
    }

    /// Get the current number of added messages
    pub fn len(&self) -> usize {
        self.message_count
    }

    /// Create a signature from the builder
    pub fn sign(self) -> Result<Signature, Error> {
        if self.message_count != self.generators.message_count() {
            return Err(err_msg!(
                Usage,
                "Message count does not match generator count"
            ));
        }
        let sk = self
            .key
            .bls_secret_scalar()
            .ok_or_else(|| err_msg!(MissingSecretKey))?;
        if sk == &Scalar::zero() {
            return Err(err_msg!(MissingSecretKey));
        }
        let mut hash_es = self.hash_es.clone();
        hash_es.update(sk.to_bytes());
        let mut hash_read = hash_es.finalize();
        let e = hash_read.next();
        let s = hash_read.next();
        let b = self.accum_b.sum_with(self.generators.blinding(), s);
        let a = (b * (sk + e).invert().unwrap()).to_affine();
        Ok(Signature { a, e, s })
    }
}

#[derive(Clone, Debug)]
/// A verifier for a BBS+ signature
pub struct SignatureVerifier<'g, G: Generators> {
    accum_b: AccumG1,
    generators: &'g G,
    key: &'g BlsKeyPair<G2>,
    message_count: usize,
}

impl<'g, G: Generators> SignatureVerifier<'g, G> {
    /// Create a new signature verifier
    pub fn new(generators: &'g G, key: &'g BlsKeyPair<G2>) -> Self {
        Self {
            accum_b: AccumG1::new_with(G1Projective::generator()),
            generators,
            key,
            message_count: 0,
        }
    }
}

impl<G: Generators> SignatureVerifier<'_, G> {
    /// Push a signed message
    pub fn push_message(&mut self, message: Message) -> Result<(), Error> {
        let c = self.message_count;
        if c >= self.generators.message_count() {
            return Err(err_msg!(Usage, "Message index exceeds generator count"));
        }
        self.accum_b.push(self.generators.message(c), message.0);
        self.message_count = c + 1;
        Ok(())
    }

    /// Push a sequence of signed messages
    pub fn append_messages(
        &mut self,
        messages: impl IntoIterator<Item = Message>,
    ) -> Result<(), Error> {
        for msg in messages {
            self.push_message(msg)?;
        }
        Ok(())
    }

    /// Get the current number of added messages
    pub fn len(&self) -> usize {
        self.message_count
    }

    /// Verify a signature
    pub fn verify(&self, signature: &Signature) -> Result<(), Error> {
        if self.message_count != self.generators.message_count() {
            return Err(err_msg!(
                Usage,
                "Message count does not match generator count"
            ));
        }
        let b = self
            .accum_b
            .sum_with(self.generators.blinding(), signature.s);
        let valid: bool = pairing(
            &signature.a,
            &(G2Projective::generator() * signature.e + self.key.bls_public_key()).to_affine(),
        )
        .ct_eq(&pairing(&b.to_affine(), &G2Affine::generator()))
        .into();
        if valid {
            Ok(())
        } else {
            Err(err_msg!(Invalid))
        }
    }
}