//! Cryptography primitives and operations for Askar.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs, missing_debug_implementations, rust_2018_idioms)]
#![allow(unused_extern_crates)]

// `extern crate secure_env` is used here to include a symbol `ANativeActivity_onCreate`
// So we can get a pointer to `activity` on android, which is required to initialize the
// binding to the JVM.
#[cfg(all(target_os = "android", feature = "p256_hardware"))]
extern crate secure_env;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
#[macro_use]
extern crate std;

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

#[macro_use]
mod error;
pub use self::error::{Error, ErrorKind};

// re-export
pub use aead::generic_array;

pub mod alg;

pub mod backend;

pub mod buffer;

pub mod encrypt;

pub mod jwk;

pub mod kdf;

pub mod random;

pub mod sign;

pub mod repr;
