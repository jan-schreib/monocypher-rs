//! [Monocypher](https://monocypher.org) is a cryptographic library.
//!
//! It provides functions for authenticated encryption, hashing, password key derivation,
//! key exchange, and public key signatures.
//!
//! Visit the official [documentation](https://monocypher.org/manual/) for details.

extern crate libc;
extern crate monocypher_sys as ffi;
extern crate hex;

pub mod blake2;
pub mod lock;
pub mod unlock;
pub mod sign;
pub mod check;
pub mod utils;

pub mod argon2i;
pub mod poly1305;
pub mod key_exchange;
pub mod chacha20;