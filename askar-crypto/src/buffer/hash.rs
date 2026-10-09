use core::fmt::Debug;

use digest::Digest;

use crate::array::Array;

use crate::{buffer::WriteBuffer, error::Error};

/// A `WriteBuffer` implementation which hashes its input
#[derive(Debug)]
pub struct HashBuffer<D: Digest>(D);

impl<D: Digest> HashBuffer<D> {
    /// Create a new instance
    pub fn new() -> Self {
        Self(D::new())
    }

    /// Finalize the hasher and extract the result
    pub fn finalize(self) -> Array<u8, D::OutputSize> {
        self.0.finalize()
    }
}

impl<D: Digest> Default for HashBuffer<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Debug + Digest> WriteBuffer for HashBuffer<D> {
    fn buffer_write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.0.update(data);
        Ok(())
    }
}
