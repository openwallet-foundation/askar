#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::{fmt, ops::Range};

use super::{ResizeBuffer, WriteBuffer};
use crate::error::Error;

/// A structure wrapping a mutable pointer to a buffer
#[derive(Debug)]
pub struct Writer<'w, B: ?Sized> {
    inner: &'w mut B,
    pos: usize,
}

impl<B: ?Sized> Writer<'_, B> {
    /// Accessor for the writer position
    pub fn position(&self) -> usize {
        self.pos
    }
}

impl<'w> Writer<'w, [u8]> {
    /// Create a new writer from a mutable byte slice
    #[inline]
    pub fn from_slice(slice: &'w mut [u8]) -> Self {
        Writer {
            inner: slice,
            pos: 0,
        }
    }

    /// Create a new writer from a mutable byte slice, skipping a prefix
    #[inline]
    pub fn from_slice_position(slice: &'w mut [u8], pos: usize) -> Self {
        Writer { inner: slice, pos }
    }
}

impl Writer<'_, [u8]> {
    pub(crate) fn splice(
        &mut self,
        range: Range<usize>,
        mut iter: impl ExactSizeIterator<Item = u8>,
    ) -> Result<(), Error> {
        assert!(range.end >= range.start);
        let rem_len = range.len();
        let ins_len = iter.len();
        match ins_len {
            _ if ins_len > rem_len => {
                let diff = ins_len - rem_len;
                if self.pos + diff > self.inner.len() {
                    return Err(err_msg!(ExceededBuffer));
                }
                self.inner
                    .copy_within((range.end - diff)..self.pos, range.end);
                self.pos += diff;
            }
            _ if ins_len < rem_len => {
                let diff = rem_len - ins_len;
                self.inner
                    .copy_within(range.end..self.pos, range.end - diff);
                self.pos -= diff;
            }
            _ => {}
        }
        for idx in 0..ins_len {
            self.inner[range.start + idx] = iter.next().unwrap();
        }
        Ok(())
    }
}

impl AsRef<[u8]> for Writer<'_, [u8]> {
    fn as_ref(&self) -> &[u8] {
        &self.inner[..self.pos]
    }
}

impl AsMut<[u8]> for Writer<'_, [u8]> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner[..self.pos]
    }
}

impl WriteBuffer for Writer<'_, [u8]> {
    fn buffer_write(&mut self, data: &[u8]) -> Result<(), Error> {
        let total = self.inner.len();
        let end = self.pos + data.len();
        if end > total {
            return Err(err_msg!(ExceededBuffer));
        }
        self.inner[self.pos..end].copy_from_slice(data);
        self.pos += data.len();
        Ok(())
    }
}

impl ResizeBuffer for Writer<'_, [u8]> {
    fn buffer_insert(&mut self, pos: usize, data: &[u8]) -> Result<(), Error> {
        self.splice(pos..pos, data.iter().cloned())
    }

    fn buffer_remove(&mut self, range: Range<usize>) -> Result<(), Error> {
        assert!(range.end >= range.start);
        let diff = range.end - range.start;
        self.inner.copy_within(range.end..self.pos, range.start);
        self.pos -= diff;
        Ok(())
    }

    fn buffer_resize(&mut self, len: usize) -> Result<(), Error> {
        let len = self.pos + len;
        if len > self.inner.len() {
            return Err(err_msg!(ExceededBuffer));
        }
        self.pos = len;
        Ok(())
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<'w> Writer<'w, Vec<u8>> {
    /// Create a new writer from a mutable Vec<u8> pointer
    #[inline]
    pub fn from_vec(vec: &'w mut Vec<u8>) -> Self {
        Writer { inner: vec, pos: 0 }
    }

    /// Create a new writer from a mutable Vec<u8> pointer, skipping a prefix
    #[inline]
    pub fn from_vec_skip(vec: &'w mut Vec<u8>, pos: usize) -> Self {
        Writer { inner: vec, pos }
    }
}

impl<B: WriteBuffer + ?Sized> WriteBuffer for Writer<'_, B> {
    fn buffer_write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.inner.buffer_write(data)
    }
}

impl<B: ResizeBuffer + ?Sized> AsRef<[u8]> for Writer<'_, B> {
    fn as_ref(&self) -> &[u8] {
        &self.inner.as_ref()[self.pos..]
    }
}

impl<B: ResizeBuffer + ?Sized> AsMut<[u8]> for Writer<'_, B> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner.as_mut()[self.pos..]
    }
}

impl<B: ResizeBuffer + ?Sized> ResizeBuffer for Writer<'_, B> {
    fn buffer_insert(&mut self, pos: usize, data: &[u8]) -> Result<(), Error> {
        self.inner.buffer_insert(self.pos + pos, data)
    }

    fn buffer_remove(&mut self, range: Range<usize>) -> Result<(), Error> {
        self.inner
            .buffer_remove((self.pos + range.start)..(self.pos + range.end))
    }

    fn buffer_resize(&mut self, len: usize) -> Result<(), Error> {
        self.inner.buffer_resize(self.pos + len)
    }
}

impl<'b, B: ?Sized> Writer<'b, B> {
    /// Create a new writer from a reference to a buffer implementation
    pub fn from_buffer(buf: &'b mut B) -> Writer<'b, B> {
        Writer { inner: buf, pos: 0 }
    }
}

impl<'b, B: ?Sized> fmt::Write for Writer<'b, B>
where
    Writer<'b, B>: WriteBuffer,
{
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.buffer_write(s.as_bytes()).map_err(|_| fmt::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_buffer_slice() {
        let mut buf = [0u8; 10];
        let mut w = Writer::from_slice(&mut buf);
        w.buffer_write(b"he").unwrap();
        w.buffer_write(b"y").unwrap();
        assert_eq!(w.position(), 3);
        assert_eq!(&buf[..3], b"hey");
    }
}
