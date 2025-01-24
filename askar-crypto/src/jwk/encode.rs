use core::fmt::Write;

use serde::{
    ser::{Serialize, SerializeMap},
    Serializer,
};

use super::{ops::KeyOpsSet, ToJwk};
use crate::{
    alg::KeyAlg,
    buffer::{WriteBuffer, Writer},
    error::Error,
};

fn write_hex_buffer(mut buffer: impl Write, value: &[u8]) -> Result<(), Error> {
    write!(
        buffer,
        "{}",
        base64::display::Base64Display::new(
            value,
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
        )
    )
    .map_err(|_| err_msg!(Unexpected, "Error writing to JWK buffer"))
}

/// Supported modes for JWK encoding
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JwkEncoderMode {
    /// Encoding a public key
    PublicKey,
    /// Encoding a secret key
    SecretKey,
    /// Encoding a public key thumbprint
    Thumbprint,
}

/// Common interface for JWK encoders
pub trait JwkEncoder {
    /// Get the requested algorithm for the JWK
    fn alg(&self) -> Option<KeyAlg>;

    /// Add a string attribute
    fn add_str(&mut self, key: &str, value: &str) -> Result<(), Error>;

    /// Add a binary attribute to be encoded as unpadded base64-URL
    fn add_as_base64(&mut self, key: &str, value: &[u8]) -> Result<(), Error>;

    /// Accessor for the encoder mode
    fn mode(&self) -> JwkEncoderMode;

    /// Check if the mode is public
    fn is_public(&self) -> bool {
        matches!(self.mode(), JwkEncoderMode::PublicKey)
    }

    /// Check if the mode is secret
    fn is_secret(&self) -> bool {
        matches!(self.mode(), JwkEncoderMode::SecretKey)
    }

    /// Check if the mode is thumbprint
    fn is_thumbprint(&self) -> bool {
        matches!(self.mode(), JwkEncoderMode::Thumbprint)
    }
}

/// A helper structure which writes a JWK to a buffer
#[derive(Debug)]
pub struct JwkBufferEncoder<'b, B: WriteBuffer> {
    mode: JwkEncoderMode,
    buffer: &'b mut B,
    empty: bool,
    alg: Option<KeyAlg>,
    key_ops: Option<KeyOpsSet>,
    kid: Option<&'b str>,
}

impl<'b, B: WriteBuffer> JwkBufferEncoder<'b, B> {
    /// Create a new instance
    pub fn new(buffer: &'b mut B, mode: JwkEncoderMode) -> Self {
        Self {
            mode,
            buffer,
            empty: true,
            alg: None,
            key_ops: None,
            kid: None,
        }
    }

    fn start_attr(&mut self, key: &str) -> Result<(), Error> {
        let buffer = &mut *self.buffer;
        if self.empty {
            buffer.buffer_write(b"{\"")?;
            self.empty = false;
        } else {
            buffer.buffer_write(b",\"")?;
        }
        buffer.buffer_write(key.as_bytes())?;
        buffer.buffer_write(b"\":")?;
        Ok(())
    }

    /// Set the key algorithm
    pub fn alg(self, alg: Option<KeyAlg>) -> Self {
        Self { alg, ..self }
    }

    /// Set the supported key operations
    pub fn key_ops(self, key_ops: Option<KeyOpsSet>) -> Self {
        Self { key_ops, ..self }
    }

    /// Set the key identifier
    pub fn kid(self, kid: Option<&'b str>) -> Self {
        Self { kid, ..self }
    }

    /// Complete the JWK output
    pub fn finalize(mut self) -> Result<(), Error> {
        if let Some(ops) = self.key_ops {
            self.start_attr("key_ops")?;
            let buffer = &mut *self.buffer;
            for (idx, op) in ops.into_iter().enumerate() {
                if idx > 0 {
                    buffer.buffer_write(b",\"")?;
                } else {
                    buffer.buffer_write(b"\"")?;
                }
                buffer.buffer_write(op.as_str().as_bytes())?;
                buffer.buffer_write(b"\"")?;
            }
            buffer.buffer_write(b"]")?;
        }
        if let Some(kid) = self.kid {
            self.add_str("kid", kid)?;
        }
        if !self.empty {
            self.buffer.buffer_write(b"}")?;
        }
        Ok(())
    }
}

impl<B: WriteBuffer> JwkEncoder for JwkBufferEncoder<'_, B> {
    #[inline]
    fn alg(&self) -> Option<KeyAlg> {
        self.alg
    }

    fn add_str(&mut self, key: &str, value: &str) -> Result<(), Error> {
        self.start_attr(key)?;
        let buffer = &mut *self.buffer;
        buffer.buffer_write(b"\"")?;
        buffer.buffer_write(value.as_bytes())?;
        buffer.buffer_write(b"\"")?;
        Ok(())
    }

    fn add_as_base64(&mut self, key: &str, value: &[u8]) -> Result<(), Error> {
        self.start_attr(key)?;
        let buffer = &mut *self.buffer;
        buffer.buffer_write(b"\"")?;
        write_hex_buffer(Writer::from_buffer(&mut *buffer), value)?;
        buffer.buffer_write(b"\"")?;
        Ok(())
    }

    #[inline]
    fn mode(&self) -> JwkEncoderMode {
        self.mode
    }
}

/// A wrapper type for serializing a JWK using serde
#[derive(Debug)]
pub struct JwkSerialize<'s, K: ToJwk> {
    mode: JwkEncoderMode,
    key: &'s K,
    alg: Option<KeyAlg>,
    key_ops: Option<KeyOpsSet>,
    kid: Option<&'s str>,
}

impl<'s, K: ToJwk> JwkSerialize<'s, K> {
    /// Create a new instance
    pub fn new(key: &'s K, mode: JwkEncoderMode) -> Self {
        Self {
            alg: None,
            mode,
            key,
            key_ops: None,
            kid: None,
        }
    }

    /// Create a new instance for encoding a public key
    pub fn as_public(key: &'s K) -> Self {
        Self {
            mode: JwkEncoderMode::PublicKey,
            key,
            alg: None,
            key_ops: None,
            kid: None,
        }
    }

    /// Create a new instance for encoding a secret key
    pub fn as_secret(key: &'s K) -> Self {
        Self {
            mode: JwkEncoderMode::SecretKey,
            key,
            alg: None,
            key_ops: None,
            kid: None,
        }
    }

    /// Create a new instance for encoding a JWK thumbprint
    pub fn as_thumbprint(key: &'s K) -> Self {
        Self {
            mode: JwkEncoderMode::Thumbprint,
            key,
            alg: None,
            key_ops: None,
            kid: None,
        }
    }

    /// Set the key algorithm
    pub fn alg(self, alg: Option<KeyAlg>) -> Self {
        Self { alg, ..self }
    }

    /// Set the key operations
    pub fn key_ops(self, key_ops: Option<KeyOpsSet>) -> Self {
        Self { key_ops, ..self }
    }

    /// Set the key ID
    pub fn kid(self, kid: Option<&'s str>) -> Self {
        Self { kid, ..self }
    }
}

impl<K: ToJwk> Serialize for JwkSerialize<'_, K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        struct Enc<'m, M> {
            alg: Option<KeyAlg>,
            mode: JwkEncoderMode,
            map: &'m mut M,
        }

        impl<M: SerializeMap> JwkEncoder for Enc<'_, M> {
            fn alg(&self) -> Option<KeyAlg> {
                self.alg
            }

            fn add_str(&mut self, key: &str, value: &str) -> Result<(), Error> {
                self.map
                    .serialize_entry(key, value)
                    .map_err(|_| err_msg!(Unexpected, "Error serializing JWK"))
            }

            fn add_as_base64(&mut self, key: &str, value: &[u8]) -> Result<(), Error> {
                // in practice these values have a limited length.
                // it would be nice to use collect_str, but that's not supported by serde-json-core.
                let mut buf = [0u8; 256];
                let mut w = Writer::from_slice(&mut buf);
                write_hex_buffer(&mut w, value)?;
                self.map
                    .serialize_entry(key, core::str::from_utf8(w.as_ref()).unwrap())
                    .map_err(|_| err_msg!(Unexpected, "Error serializing JWK"))
            }

            fn mode(&self) -> JwkEncoderMode {
                self.mode
            }
        }

        let mut map = serializer.serialize_map(None)?;
        let mut enc = Enc {
            alg: self.alg,
            mode: self.mode,
            map: &mut map,
        };
        self.key
            .encode_jwk(&mut enc)
            .map_err(|err| <S::Error as serde::ser::Error>::custom(err.message()))?;
        if let Some(ops) = self.key_ops {
            map.serialize_entry("key_ops", &ops)?;
        }
        if let Some(kid) = self.kid {
            map.serialize_entry("kid", kid)?;
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "ed25519")]
    #[test]
    fn serialize_jwk() {
        use super::JwkSerialize;
        use crate::{
            alg::ed25519::Ed25519KeyPair,
            jwk::{JwkParts, KeyOps},
            repr::KeySecretBytes,
        };

        let kp = Ed25519KeyPair::from_secret_bytes(&hex!(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        ))
        .unwrap();
        let mut buf = [0u8; 512];
        let len = serde_json_core::to_slice(
            &JwkSerialize::as_secret(&kp)
                .kid(Some("FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ"))
                .key_ops(Some(KeyOps::Sign | KeyOps::Verify)),
            &mut buf,
        )
        .unwrap();
        let parts = JwkParts::from_slice(&buf[..len]).unwrap();
        assert_eq!(parts.kty, "OKP");
        assert_eq!(
            parts.kid,
            Some("FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ")
        );
        assert_eq!(parts.crv, Some("Ed25519"));
        assert_eq!(parts.x, Some("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"));
        assert_eq!(parts.y, None);
        assert_eq!(parts.d, Some("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"));
        assert_eq!(parts.k, None);
        assert_eq!(parts.key_ops, Some(KeyOps::Sign | KeyOps::Verify));
    }
}
