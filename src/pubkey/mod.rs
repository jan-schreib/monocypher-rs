use monocypher_sys as ffi;
use std::mem;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Signature check failed!")]
    Signature,
}

#[derive(Debug)]
pub struct KeyPair {
    pub secret_key: [u8; 64],
    pub public_key: [u8; 32],
}

impl KeyPair {
    pub fn generate_key_pair(mut seed: [u8; 32]) -> Self {
        let mut secret_key = [0; 64];
        let mut public_key = [0; 32];

        unsafe {
            ffi::crypto_eddsa_key_pair(
                secret_key.as_mut_ptr(),
                public_key.as_mut_ptr(),
                seed.as_mut_ptr(),
            )
        }

        Self {
            secret_key,
            public_key,
        }
    }
}

pub fn check(signature: [u8; 64], public_key: [u8; 32], message: &[u8]) -> Result<(), Error> {
    unsafe {
        if ffi::crypto_eddsa_check(
            signature.as_ptr(),
            public_key.as_ptr(),
            message.as_ptr(),
            message.len(),
        ) == 0
        {
            return Ok(());
        }
        Err(Error::Signature)
    }
}

/// Signs a message with the secret_key.
pub fn sign(secret_key: [u8; 64], message: &[u8]) -> [u8; 64] {
    unsafe {
        let mut signature = mem::MaybeUninit::<[u8; 64]>::uninit();
        ffi::crypto_eddsa_sign(
            signature.as_mut_ptr() as *mut u8,
            secret_key.as_ptr(),
            message.as_ptr(),
            message.len(),
        );

        signature.assume_init()
    }
}

#[cfg(test)]
mod test {
    use crate::pubkey::{check, sign, KeyPair};

    #[test]
    fn sign_test() {
        let keypair = KeyPair::generate_key_pair([0; 32]);

        let sig = sign(keypair.secret_key, "test".as_bytes());

        assert_eq!(
            sig[0..32],
            [
                207, 91, 41, 236, 159, 45, 246, 167, 208, 55, 137, 29, 156, 107, 240, 221, 172,
                159, 159, 162, 42, 233, 194, 79, 6, 163, 198, 22, 124, 218, 51, 85
            ]
        );
        assert_eq!(
            sig[32..63],
            [
                132, 36, 230, 53, 3, 132, 56, 195, 137, 117, 116, 182, 117, 84, 183, 131, 19, 180,
                50, 118, 249, 197, 24, 179, 154, 184, 106, 232, 241, 189, 108
            ]
        )
    }

    #[test]
    fn check_valid() {
        let keypair = KeyPair::generate_key_pair([0; 32]);

        let sig = sign(keypair.secret_key, "test".as_bytes());

        let ret = check(sig, keypair.public_key, "test".as_bytes());

        assert_eq!(ret.is_ok(), true)
    }

    #[test]
    fn check_forged() {
        let keypair = KeyPair::generate_key_pair([0; 32]);

        let sig = sign(keypair.secret_key, "test".as_bytes());

        let ret = check(sig, keypair.public_key, "not_test".as_bytes());

        assert_eq!(ret.is_err(), true)
    }
}
