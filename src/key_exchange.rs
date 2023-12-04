//! Elliptic Curve Diffie-Hellman key exchange
//!
//! //! [Official documentation](https://monocypher.org/manual/key_exchange)

use monocypher_sys as ffi;
use std::mem;

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
        let mut public_key = mem::MaybeUninit::<[u8; 32]>::uninit();
        ffi::crypto_x25519_public_key(public_key.as_mut_ptr() as *mut u8, secret_key.as_ptr());
        public_key.assume_init()
    }
}

#[cfg(test)]
mod test {
    use crate::key_exchange;

    #[test]
    fn public() {
        let secret_key = [2u8; 32];
        let public_key = key_exchange::public(secret_key);

        assert_eq!(
            public_key,
            [
                206, 141, 58, 209, 204, 182, 51, 236, 123, 112, 193, 120, 20, 165, 199, 110, 205,
                2, 150, 133, 5, 13, 52, 71, 69, 186, 5, 135, 14, 88, 125, 89
            ]
        )
    }
}
