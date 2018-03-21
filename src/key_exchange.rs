//! Elliptic Curve Diffie-Hellman key exchange

use ffi;
use std::mem;

/// Computes a shared key with your secret key and their public key.
///
/// # Example
///
/// ```
/// use monocypher::key_exchange::shared;
///
/// let pubkey = [1u8; 32];
/// shared([31u8; 32], pubkey);
/// ```
pub fn shared(secret_key: [u8; 32], their_public_key: [u8; 32]) -> Result<[u8; 32], String> {
    unsafe {
        let mut shared_key: [u8; 32] = mem::uninitialized();
        if ffi::crypto_key_exchange(
            shared_key.as_mut_ptr(),
            secret_key.as_ptr(),
            their_public_key.as_ptr(),
        ) == 0
        {
            return Ok(shared_key);
        }
        Err("Their public key is malicious!".to_owned())
    }
}

/// Deterministically computes the public key from a random secret key.
///
/// # Example
/// ```
/// use monocypher::key_exchange::public;
///
/// let secret_key = [2u8; 32];
/// public(secret_key);
/// ```
pub fn public(secret_key: [u8; 32]) -> [u8; 32] {
    unsafe {
        let mut public_key: [u8; 32] = mem::uninitialized();
        ffi::crypto_x25519_public_key(public_key.as_mut_ptr(), secret_key.as_ptr());
        public_key
    }
}
