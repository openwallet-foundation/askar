use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};

use crate::crypto::{Error as CryptoError, ErrorKind as CryptoErrorKind};

/// The possible kinds of error produced by the crate
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// An unexpected error from the store backend
    Backend,

    /// The store backend was too busy to handle the request
    Busy,

    /// A custom error type for external integrations
    Custom,

    /// An insert operation failed due to a unique key conflict
    Duplicate,

    /// An encryption or decryption operation failed
    Encryption,

    /// The input parameters to the method were incorrect
    Input,

    /// The requested record was not found
    NotFound,

    /// An unexpected error occurred
    Unexpected,

    /// An unsupported operation was requested
    Unsupported,
}

impl ErrorKind {
    /// Convert the error kind to a string reference
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Backend => "Backend error",
            Self::Busy => "Busy",
            Self::Custom => "Custom error",
            Self::Duplicate => "Duplicate",
            Self::Encryption => "Encryption error",
            Self::Input => "Input error",
            Self::NotFound => "Not found",
            Self::Unexpected => "Unexpected error",
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
    pub(crate) cause: Option<Box<dyn StdError + Send + Sync + 'static>>,
    pub(crate) message: Option<String>,
}

impl Error {
    pub(crate) fn from_msg<T: Into<String>>(kind: ErrorKind, msg: T) -> Self {
        Self {
            kind,
            cause: None,
            message: Some(msg.into()),
        }
    }

    /// Accessor for the error kind
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Accessor for the error message
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Split the error into its components
    pub fn into_parts(
        self,
    ) -> (
        ErrorKind,
        Option<Box<dyn StdError + Send + Sync + 'static>>,
        Option<String>,
    ) {
        (self.kind, self.cause, self.message)
    }

    pub(crate) fn with_cause<T: Into<Box<dyn StdError + Send + Sync + 'static>>>(
        mut self,
        err: T,
    ) -> Self {
        self.cause = Some(err.into());
        self
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(msg) = self.message.as_ref() {
            f.write_str(msg)?;
        } else {
            f.write_str(self.kind.as_str())?;
        }
        if let Some(cause) = self.cause.as_ref() {
            write!(f, "\nCaused by: {}", cause)?;
        }
        Ok(())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.cause
            .as_ref()
            .map(|err| &**err as &(dyn StdError + 'static))
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
            cause: None,
            message: None,
        }
    }
}

// FIXME would be preferable to remove this auto-conversion and handle
// all sqlx errors manually, to ensure there is some context around the error
#[cfg(any(feature = "postgres", feature = "sqlite"))]
impl From<sqlx::Error> for Error {
    fn from(err: sqlx::Error) -> Self {
        Error::from(ErrorKind::Backend).with_cause(err)
    }
}

impl From<CryptoError> for Error {
    fn from(err: CryptoError) -> Self {
        let kind = match err.kind() {
            CryptoErrorKind::Custom => ErrorKind::Custom,
            CryptoErrorKind::Encryption => ErrorKind::Encryption,
            CryptoErrorKind::ExceededBuffer | CryptoErrorKind::Unexpected => ErrorKind::Unexpected,
            CryptoErrorKind::Invalid
            | CryptoErrorKind::InvalidKeyData
            | CryptoErrorKind::InvalidNonce
            | CryptoErrorKind::MissingSecretKey
            | CryptoErrorKind::Usage => ErrorKind::Input,
            CryptoErrorKind::Unsupported => ErrorKind::Unsupported,
        };
        Error::from_msg(kind, err.message())
    }
}

macro_rules! err_msg {
    () => {
        $crate::error::Error::from($crate::error::ErrorKind::Input)
    };
    ($kind:ident) => {
        $crate::error::Error::from($crate::error::ErrorKind::$kind)
    };
    ($kind:ident, $($args:tt)+) => {
        $crate::error::Error::from_msg($crate::error::ErrorKind::$kind, format!($($args)+))
    };
    ($($args:tt)+) => {
        $crate::error::Error::from_msg($crate::error::ErrorKind::Input, format!($($args)+))
    };
}

macro_rules! err_map {
    ($($params:tt)*) => {
        |err| err_msg!($($params)*).with_cause(err)
    };
}
