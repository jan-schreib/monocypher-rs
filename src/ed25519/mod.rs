//! ED25519 public key signatures
//!
//! [Official documentation](https://monocypher.org/manual/optional/ed25519)

use crate::{Error, KeyPair, PrivKey, PubKey, PubPrivKey, Seed, Signature};
use derive_more::From;
use monocypher_sys as ffi;
use std::mem;

#[derive(Debug, From)]
pub struct PrivateKey([u8; 64]);

#[derive(Debug, From)]
pub struct PublicKey([u8; 32]);

impl PrivKey for PrivateKey {
    /// Signs a message with the secret_key.
    fn sign(&self, message: &[u8]) -> Signature {
        unsafe {
            let mut signature = mem::MaybeUninit::<[u8; 64]>::uninit();
            ffi::crypto_ed25519_sign(
                signature.as_mut_ptr() as *mut u8,
                self.0.as_ptr(),
                message.as_ptr(),
                message.len(),
            );

            Signature::from(signature.assume_init())
        }
    }
}

impl PubKey for PublicKey {
    fn check(&self, signature: crate::Signature, message: &[u8]) -> Result<(), crate::Error> {
        unsafe {
            if ffi::crypto_ed25519_check(
                signature.as_ptr(),
                self.0.as_ptr(),
                message.as_ptr(),
                message.len(),
            ) == 0
            {
                return Ok(());
            }
            Err(Error::Signature)
        }
    }
}

impl PubPrivKey for KeyPair<PrivateKey, PublicKey> {
    /// Generates a public private key pair
    fn generate_key_pair(mut seed: Seed) -> Self {
        let mut private_key = [0; 64];
        let mut public_key = [0; 32];
        unsafe {
            ffi::crypto_ed25519_key_pair(
                private_key.as_mut_ptr(),
                public_key.as_mut_ptr(),
                seed.as_mut_ptr(),
            );
        }

        Self {
            private_key: PrivateKey::from(private_key),
            public_key: PublicKey::from(public_key),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        ed25519::{self, KeyPair},
        PubPrivKey, Seed,
    };

    #[test]
    fn public_key_test() {
        let seed = Seed::from([2u8; 32]);
        let keypair: KeyPair<ed25519::PrivateKey, ed25519::PublicKey> =
            KeyPair::generate_key_pair(seed);

        assert_eq!(
            keypair.public_key.0,
            [
                129, 57, 119, 14, 168, 125, 23, 95, 86, 163, 84, 102, 195, 76, 126, 204, 203, 141,
                138, 145, 180, 238, 55, 162, 93, 246, 15, 91, 143, 201, 179, 148,
            ]
        );
    }

    #[test]
    fn sign_test() {
        let seed = Seed::from([2u8; 32]);
        let keypair: KeyPair<ed25519::PrivateKey, ed25519::PublicKey> =
            KeyPair::generate_key_pair(seed);

        let sig = keypair.sign("test".as_bytes());

        assert_eq!(
            sig[0..64],
            [
                51, 31, 122, 122, 55, 25, 128, 21, 92, 76, 172, 182, 240, 213, 40, 108, 108, 219,
                11, 163, 70, 48, 118, 93, 44, 189, 251, 26, 172, 202, 182, 82, 114, 198, 225, 139,
                215, 224, 85, 7, 101, 60, 23, 81, 127, 31, 137, 113, 188, 222, 211, 151, 63, 175,
                13, 242, 227, 146, 187, 36, 138, 186, 134, 3,
            ]
        );
    }

    #[test]
    fn check_test() {
        let seed = Seed::from([2u8; 32]);
        let keypair: KeyPair<ed25519::PrivateKey, ed25519::PublicKey> =
            KeyPair::generate_key_pair(seed);

        let sig = keypair.sign("test".as_bytes());

        let ret = keypair.check(sig, "test".as_bytes());

        assert_eq!(ret.is_ok(), true)
    }

    #[test]
    fn check_forged() {
        let seed = Seed::from([2u8; 32]);
        let keypair: KeyPair<ed25519::PrivateKey, ed25519::PublicKey> =
            KeyPair::generate_key_pair(seed);

        let sig = keypair.sign("test".as_bytes());

        let ret = keypair.check(sig, "not_test".as_bytes());

        assert_eq!(ret.is_err(), true)
    }
}
