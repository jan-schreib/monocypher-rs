//! [Monocypher](https://monocypher.org) is a cryptographic library.
//!
//! It provides functions for authenticated encryption, hashing, password key derivation,
//! key exchange, and public key signatures.
//!
//! Visit the official [documentation](https://monocypher.org/manual/) for details.

use derive_more::From;
use std::ops::{Deref, DerefMut};
use thiserror::Error;

pub mod aead;
pub mod hashing;
pub mod password;
pub mod pubkey;
pub mod utils;

pub mod key_exchange;
pub mod poly1305;

#[cfg(feature = "ed25519")]
pub mod ed25519;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Signature check failed!")]
    Signature,
}
#[derive(Debug)]
pub struct KeyPair<S, P>
where
    S: PrivKey,
    P: PubKey,
{
    pub private_key: S,
    pub public_key: P,
}

impl<S, P> KeyPair<S, P>
where
    S: PrivKey,
    P: PubKey,
{
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.private_key.sign(message)
    }

    pub fn check(&self, signature: Signature, message: &[u8]) -> Result<(), Error> {
        self.public_key.check(signature, message)
    }
}

#[derive(Debug, From)]
pub struct Signature([u8; 64]);

impl Deref for Signature {
    type Target = [u8; 64];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, From)]
pub struct Seed([u8; 32]);

impl Deref for Seed {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Seed {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub trait PubPrivKey {
    fn generate_key_pair(seed: Seed) -> Self;
}

pub trait PrivKey {
    fn sign(&self, message: &[u8]) -> Signature;
}
pub trait PubKey {
    fn check(&self, signature: Signature, message: &[u8]) -> Result<(), Error>;
}
