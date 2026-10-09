//! ConcatKDF from NIST 800-56ar for ECDH-ES / ECDH-1PU

use core::{fmt::Debug, marker::PhantomData};

use digest::{Digest, FixedOutputReset};

use crate::array::{typenum::Unsigned, Array};

use crate::{buffer::WriteBuffer, error::Error};

/// A struct providing the key derivation for a particular hash function
#[derive(Clone, Copy, Debug)]
pub struct ConcatKDF<H>(PhantomData<H>);

/// Parameters for the key derivation
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConcatKDFParams<'p> {
    /// The algorithm name
    pub alg: &'p [u8],
    /// Sender identifier (PartyUInfo)
    pub apu: &'p [u8],
    /// Recipient identifier (PartyVInfo)
    pub apv: &'p [u8],
    /// SuppPubInfo as defined by the application
    pub pub_info: &'p [u8],
    /// SuppPrivInfo as defined by the application
    pub prv_info: &'p [u8],
}

impl<H> ConcatKDF<H>
where
    H: Digest + FixedOutputReset,
{
    /// Perform the key derivation and write the result to the provided buffer
    pub fn derive_key(
        message: &[u8],
        params: ConcatKDFParams<'_>,
        mut output: &mut [u8],
    ) -> Result<(), Error> {
        let output_len = output.len();
        if output_len > H::OutputSize::USIZE * (u32::MAX as usize) - 1 {
            return Err(err_msg!(Usage, "Exceeded max output size for concat KDF"));
        }
        let mut hasher = ConcatKDFHash::<H>::new();
        let mut remain = output_len;
        while remain > 0 {
            hasher.start_pass();
            hasher.hash_message(message);
            hasher.hash_params(params);
            let hashed = hasher.finish_pass();
            let cp_size = hashed.len().min(remain);
            output[..cp_size].copy_from_slice(&hashed[..cp_size]);
            output = &mut output[cp_size..];
            remain -= cp_size;
        }
        Ok(())
    }
}

/// Core hashing implementation of the multi-pass key derivation
#[derive(Debug)]
pub struct ConcatKDFHash<H: Digest> {
    hasher: H,
    counter: u32,
}

impl<H: Digest> ConcatKDFHash<H> {
    /// Create a new instance
    pub fn new() -> Self {
        Self {
            hasher: H::new(),
            counter: 1,
        }
    }

    /// Start a new pass of the key derivation
    pub fn start_pass(&mut self) {
        self.hasher.update(self.counter.to_be_bytes());
        self.counter += 1;
    }

    /// Hash input to the key derivation
    pub fn hash_message(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Hash the parameters of the key derivation
    pub fn hash_params(&mut self, params: ConcatKDFParams<'_>) {
        let hash = &mut self.hasher;
        hash.update((params.alg.len() as u32).to_be_bytes());
        hash.update(params.alg);
        hash.update((params.apu.len() as u32).to_be_bytes());
        hash.update(params.apu);
        hash.update((params.apv.len() as u32).to_be_bytes());
        hash.update(params.apv);
        hash.update(params.pub_info);
        hash.update(params.prv_info);
    }

    /// Complete this pass of the key derivation, returning the result
    pub fn finish_pass(&mut self) -> Array<u8, H::OutputSize>
    where
        H: FixedOutputReset,
    {
        self.hasher.finalize_reset()
    }
}

impl<H: Digest> Default for ConcatKDFHash<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Debug + Digest> WriteBuffer for ConcatKDFHash<D> {
    fn buffer_write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.hasher.update(data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    #[test]
    // testing with ConcatKDF - single pass via ConcatKDFHash is tested elsewhere
    fn expected_1pu_output() {
        let z = hex!(
            "9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4
            e3ca3474384c9f62b30bfd4c688b3e7d4110a1b4badc3cc54ef7b81241efd50d"
        );
        let mut output = [0u8; 32];
        ConcatKDF::<Sha256>::derive_key(
            &z,
            ConcatKDFParams {
                alg: b"A256GCM",
                apu: b"Alice",
                apv: b"Bob",
                pub_info: &(256u32).to_be_bytes(),
                prv_info: &[],
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(
            output,
            hex!("6caf13723d14850ad4b42cd6dde935bffd2fff00a9ba70de05c203a5e1722ca7")
        );
    }
}
