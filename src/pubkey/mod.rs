use derive_more::From;
use monocypher_sys as ffi;
use std::mem;

use crate::{Error, KeyPair, PrivKey, PubKey, PubPrivKey, Seed, Signature};

#[derive(Debug, From)]
pub struct PrivateKey([u8; 64]);

#[derive(Debug, From)]
pub struct PublicKey([u8; 32]);

impl PrivKey for PrivateKey {
    /// Signs a message with the secret_key.
    fn sign(&self, message: &[u8]) -> Signature {
        unsafe {
            let mut signature = mem::MaybeUninit::<[u8; 64]>::uninit();
            ffi::crypto_eddsa_sign(
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
    fn check(&self, signature: Signature, message: &[u8]) -> Result<(), Error> {
        unsafe {
            if ffi::crypto_eddsa_check(
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
            private_key: PrivateKey::from(secret_key),
            public_key: PublicKey::from(public_key),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::pubkey::{self, KeyPair};
    use crate::{PrivKey, PubPrivKey, Seed};

    #[test]
    fn sign_test() {
        let keypair: KeyPair<pubkey::PrivateKey, pubkey::PublicKey> =
            KeyPair::generate_key_pair(Seed::from([0; 32]));

        let sig = keypair.private_key.sign("test".as_bytes());

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
        let keypair: KeyPair<pubkey::PrivateKey, pubkey::PublicKey> =
            KeyPair::generate_key_pair(Seed::from([0; 32]));
        let sig = keypair.sign("test".as_bytes());

        let ret = keypair.check(sig, "test".as_bytes());

        assert_eq!(ret.is_ok(), true)
    }

    #[test]
    fn check_forged() {
        let keypair: KeyPair<pubkey::PrivateKey, pubkey::PublicKey> =
            KeyPair::generate_key_pair(Seed::from([0; 32]));
        let sig = keypair.sign("test".as_bytes());

        let ret = keypair.check(sig, "not_test".as_bytes());

        assert_eq!(ret.is_err(), true)
    }
}
