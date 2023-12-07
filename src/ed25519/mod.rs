//! ED25519 public key signatures
//!
//! [Official documentation](https://monocypher.org/manual/optional/ed25519)

use monocypher_sys as ffi;
use std::mem;

#[derive(Debug)]
pub struct KeyPair {
    pub secret_key: [u8; 64],
    pub public_key: [u8; 32],
}

impl KeyPair {
    /// Computes the public key of the specified secret key.
    pub fn generate_key_pair(mut seed: [u8; 32]) -> KeyPair {
        let mut secret_key = [0; 64];
        let mut public_key = [0; 32];
        unsafe {
            ffi::crypto_ed25519_key_pair(
                secret_key.as_mut_ptr(),
                public_key.as_mut_ptr(),
                seed.as_mut_ptr(),
            );
        }

        KeyPair {
            secret_key,
            public_key,
        }
    }
}

/// Signs a message with a secret_key.
/// The public key is optional, and will be recomputed if not provided.
/// This recomputation doubles the execution time.
pub fn sign(secret_key: [u8; 64], message: &[u8]) -> [u8; 64] {
    unsafe {
        let mut signature = mem::MaybeUninit::<[u8; 64]>::uninit();
        ffi::crypto_ed25519_sign(
            signature.as_mut_ptr() as *mut u8,
            secret_key.as_ptr(),
            message.as_ptr(),
            message.len(),
        );

        signature.assume_init()
    }
}

pub fn check(signature: [u8; 64], public_key: [u8; 32], message: &[u8]) -> Result<(), String> {
    unsafe {
        if ffi::crypto_ed25519_check(
            signature.as_ptr(),
            public_key.as_ptr(),
            message.as_ptr(),
            message.len(),
        ) == 0
        {
            return Ok(());
        }
        Err("Forged message detected.".to_owned())
    }
}

#[cfg(test)]
mod test {
    use crate::ed25519::{check, sign, KeyPair};

    #[test]
    fn public_key_test() {
        let seed = [2u8; 32];
        let keypair = KeyPair::generate_key_pair(seed);

        assert_eq!(
            keypair.public_key,
            [
                129, 57, 119, 14, 168, 125, 23, 95, 86, 163, 84, 102, 195, 76, 126, 204, 203, 141,
                138, 145, 180, 238, 55, 162, 93, 246, 15, 91, 143, 201, 179, 148,
            ]
        );
    }

    #[test]
    fn sign_test() {
        let seed = [2u8; 32];
        let keypair = KeyPair::generate_key_pair(seed);

        let sig = sign(keypair.secret_key, "test".as_bytes());

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
        let seed = [2u8; 32];
        let keypair = KeyPair::generate_key_pair(seed);

        let sig = sign(keypair.secret_key, "test".as_bytes());

        let ret = check(sig, keypair.public_key, "test".as_bytes());

        assert_eq!(ret.is_ok(), true)
    }

    #[test]
    fn check_forged() {
        let seed = [2u8; 32];
        let keypair = KeyPair::generate_key_pair(seed);

        let sig = sign(keypair.secret_key, "test".as_bytes());

        let ret = check(sig, keypair.public_key, "not_test".as_bytes());

        assert_eq!(ret.is_err(), true)
    }
}
