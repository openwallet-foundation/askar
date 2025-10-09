#[cfg(feature = "std")]
use alloc::boxed::Box;
use core::fmt::{self, Display, Formatter};

#[cfg(feature = "std")]
use std::error::Error as StdError;

/// The possible kinds of error produced by the crate
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// Custom error, for use external integrations
    Custom,

    /// An encryption or decryption operation failed
    Encryption,

    /// Out of space in provided buffer
    ExceededBuffer,

    /// The provided input was invalid
    Invalid,

    /// The provided key was invalid
    InvalidKeyData,

    /// The provided nonce was invalid (bad length)
    InvalidNonce,

    /// A secret key is required but not present
    MissingSecretKey,

    /// An unexpected error occurred
    Unexpected,

    /// The input parameters to the method were incorrect
    Usage,

    /// An unsupported operation was requested
    Unsupported,
}

impl ErrorKind {
    /// Convert the error kind to a string reference
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Custom => "Custom error",
            Self::Encryption => "Encryption error",
            Self::ExceededBuffer => "Exceeded buffer size",
            Self::Invalid => "Invalid input",
            Self::InvalidNonce => "Invalid encryption nonce",
            Self::InvalidKeyData => "Invalid key data",
            Self::MissingSecretKey => "Missing secret key",
            Self::Unexpected => "Unexpected error",
            Self::Usage => "Usage error",
            Self::Unsupported => "Unsupported",
        }
    }
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The standard crate error type
#[derive(Debug)]
pub struct Error {
    pub(crate) kind: ErrorKind,
    #[cfg(feature = "std")]
    pub(crate) cause: Option<Box<dyn StdError + Send + Sync + 'static>>,
    pub(crate) message: Option<&'static str>,
}

impl Error {
    /// Create a new error instance with message text
    pub fn from_msg(kind: ErrorKind, msg: &'static str) -> Self {
        Self {
            kind,
            #[cfg(feature = "std")]
            cause: None,
            message: Some(msg),
        }
    }

    /// Accessor for the error kind
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Accessor for the error message
    pub fn message(&self) -> &'static str {
        self.message.unwrap_or_else(|| self.kind.as_str())
    }

    #[cfg(feature = "std")]
    pub(crate) fn with_cause<T: Into<Box<dyn StdError + Send + Sync>>>(mut self, err: T) -> Self {
        self.cause = Some(err.into());
        self
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(msg) = self.message {
            f.write_str(msg)?;
        } else {
            f.write_str(self.kind.as_str())?;
        }
        #[cfg(feature = "std")]
        if let Some(cause) = self.cause.as_ref() {
            write!(f, "\nCaused by: {}", cause)?;
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.cause.as_ref().map(|err| {
            // &<Error + ?Sized> implements Error, which lets us
            // create a new trait object
            (&**err) as &dyn StdError
        })
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.message == other.message
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            #[cfg(feature = "std")]
            cause: None,
            message: None,
        }
    }
}

#[macro_export]
/// Assemble an error kind and optional message
macro_rules! err_msg {
    ($kind:ident) => {
        $crate::Error::from($crate::ErrorKind::$kind)
    };
    ($kind:ident, $msg:expr) => {
        $crate::Error::from_msg($crate::ErrorKind::$kind, $msg)
    };
    ($kind:ident, $($args:tt)+) => {
        $crate::error::Error::from_msg($crate::error::ErrorKind::$kind, format!($($args)+))
    };
}

#[cfg(feature = "std")]
/// Map an external error
#[macro_export]
macro_rules! err_map {
    ($($params:tt)*) => {
        |err| err_msg!($($params)*).with_cause(err)
    };
}

#[cfg(not(feature = "std"))]
/// Map an external error
#[macro_export]
macro_rules! err_map {
    ($($params:tt)*) => {
        |_| err_msg!($($params)*)
    };
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    // ensure that the source can still be downcast
    fn downcast_err() {
        #[derive(Debug)]
        struct E;
        impl Display for E {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "E")
            }
        }
        impl StdError for E {}

        let err = Error::from(ErrorKind::Unexpected).with_cause(E);
        let e = err.source().unwrap().downcast_ref::<E>();
        assert!(e.is_some());
    }
}
