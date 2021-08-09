//! ED25519 public key signatures
//!
//! [Official documentation](https://monocypher.org/manual/optional/ed25519)

use ffi;
use std::mem;

/// Computes the public key of the specified secret key.
pub fn public_key(secret_key: [u8; 32]) -> [u8; 32] {
    unsafe {
        let mut public_key = mem::MaybeUninit::<[u8; 32]>::uninit();
        ffi::crypto_ed25519_public_key(public_key.as_mut_ptr() as *mut u8, secret_key.as_ptr());
        public_key.assume_init()
    }
}

/// Signs a message with secret_key.
/// The public key is optional, and will be recomputed if not provided.
/// This recomputation doubles the execution time.
pub fn sign(secret_key: [u8; 32], public_key: [u8; 32], message: &[u8]) -> [u8; 64] {
    unsafe {
        let mut signature = mem::MaybeUninit::<[u8; 64]>::uninit();
        ffi::crypto_ed25519_sign(
            signature.as_mut_ptr() as *mut u8,
            secret_key.as_ptr(),
            public_key.as_ptr(),
            message.as_ptr(),
            message.len() as u64,
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
            message.len() as u64,
        ) == 0
        {
            return Ok(());
        }
        Err("Forged message detected.".to_owned())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn public_key_test() {
        let secret_key = [2u8; 32];
        let public_key = public_key(secret_key);

        assert_eq!(
            public_key,
            [
                129, 57, 119, 14, 168, 125, 23, 95, 86, 163, 84, 102, 195, 76, 126, 204,
                203, 141, 138, 145, 180, 238, 55, 162, 93, 246, 15, 91, 143, 201, 179, 148,
            ]
        );
    }

    #[test]
    fn sign() {
        let secret_key = [2u8; 32];
        let public_key = public_key(secret_key);

        let sig = super::sign(secret_key, public_key, "test".as_bytes());

        assert_eq!(
            sig[0..64],
            [
                51, 31, 122, 122, 55, 25, 128, 21, 92, 76, 172, 182, 240, 213, 40, 108,
                108, 219, 11, 163, 70, 48, 118, 93, 44, 189, 251, 26, 172, 202, 182, 82,
                114, 198, 225, 139, 215, 224, 85, 7, 101, 60, 23, 81, 127, 31, 137, 113,
                188, 222, 211, 151, 63, 175, 13, 242, 227, 146, 187, 36, 138, 186, 134, 3,
            ]
        );
    }

    #[test]
    fn check() {
        let secret_key = [2u8; 32];
        let public_key = super::public_key(secret_key);

        let sig = super::sign(secret_key, public_key, "test".as_bytes());

        let ret = super::check(sig, public_key, "test".as_bytes());

        assert_eq!(ret.is_ok(), true)
    }

    #[test]
    fn check_forged() {
        let secret_key = [2u8; 32];
        let public_key = super::public_key(secret_key);

        let sig = super::sign(secret_key, public_key, "test".as_bytes());

        let ret = super::check(sig, public_key, "not_test".as_bytes());

        assert_eq!(ret.is_err(), true)
    }
}
