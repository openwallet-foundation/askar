//! Secure storage designed for Hyperledger Aries agents

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs, missing_debug_implementations, rust_2018_idioms)]

pub use askar_crypto as crypto;

#[macro_use]
mod error;
pub use self::error::{Error, ErrorKind};

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

#[macro_use]
mod macros;

#[cfg(any(test, feature = "log"))]
#[macro_use]
extern crate log;

#[cfg(feature = "migration")]
#[macro_use]
extern crate serde;

pub mod backend;
pub use self::backend::{Backend, BackendSession, ManageBackend};

#[cfg(feature = "any")]
pub mod any;

#[cfg(feature = "postgres")]
pub use self::backend::postgres;

#[cfg(feature = "sqlite")]
pub use self::backend::sqlite;

pub mod entry;

#[cfg(feature = "inspect")]
pub mod inspect;

#[doc(hidden)]
pub mod future;

#[cfg(all(feature = "migration", feature = "sqlite"))]
pub mod migration;

mod options;
pub use options::{IntoOptions, Options};

mod protect;
pub use protect::{
    generate_raw_store_key,
    kdf::{Argon2Level, KdfMethod},
    PassKey, StoreKeyMethod,
};

mod wql;
