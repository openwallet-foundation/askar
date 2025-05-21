# askar-crypto

[![Rust Crate](https://img.shields.io/crates/v/askar-crypto.svg)](https://crates.io/crates/askar-crypto)
[![Rust Documentation](https://docs.rs/askar-crypto/badge.svg)](https://docs.rs/askar-crypto)

The `askar-crypto` crate provides the basic key representations and cryptographic operations used by [`Askar`](https://github.com/openwallet-foundation/askar).

## Supported Key Types

| Key Type             | Feature   | Operations                                                    | Notes                           |
| -------------------- | --------- | ------------------------------------------------------------- | ------------------------------- |
| AES-GCM              | `aes`     | AEAD encryption<br>JWK export                                 | A128GCM and A256GCM             |
| AES-CBC-HMAC-SHA2    | `aes`     | AEAD encryption<br>JWK export                                 | A128CBC-HS256 and A256CBC-HS512 |
| AES Key Wrap         | `aes`     | Authenticated encryption<br>JWK export                        | A128KW and A256KW               |
| (X)ChaCha20-Poly1305 | `chacha`  | AEAD encryption<br>JWK export                                 | aka C20P, XC20P                 |
| BLS12-381            | `bls`     | bls-signature<sup>1</sup> key generation<br>JWK import/export | G1 and G2 key types      |
| Ed25519              | `ed25519` | EdDSA signatures<br>JWK import/export<br>Conversion to X25519 |                                 |
| X25519               | `ed25519` | DH key exchange<br>JWK import/export                          |                                 |
| K-256                | `k256`    | ECDSA signatures<br>DH key exchange<br>JWK import/export      | aka secp256k1                   |
| P-256                | `p256`    | ECDSA signatures<br>DH key exchange<br>JWK import/export      | aka nist256p1, secp256r1        |

<small>1. Compatible with bls-signature RFC draft 4 <https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04></small>

## 'Any' Key support

The `any_key` feature (which depends on `alloc`) provides a generic interface for creating and working with any supported key type.

## JSON Web Algorithms

This crate provides implementations of the [ECDH-ES](https://tools.ietf.org/html/rfc7518#section-4.6) and [ECDH-1PU (draft 4)](https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-04) key agreement operations, for use in deriving a content encryption or key wrapping key. These primitives can be used when producing or consuming JWE envelopes using these algorithms.

## no-std

This crate supports the optional `alloc` feature, gating types and operations that depend on a global allocator. The `std` feature depends on `alloc`, and adds support for `std::error::Error`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](https://github.com/openwallet-foundation/askar/blob/main/LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](https://github.com/openwallet-foundation/askar/blob/main/LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
