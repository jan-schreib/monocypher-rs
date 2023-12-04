//! Authenticated encryption w/o additional data

use monocypher_sys as ffi;
use std::mem;

/// Encrypt and authenticate plaintext with additional data.
///
/// # Example
///
/// ```
/// use monocypher::aead::lock::aead;
///
/// let plaintext = "plaintext";
/// let key = [137u8; 32];
/// let nonce = [120u8; 24];
/// let ad = "data";
///
/// let cymac = aead(plaintext.as_bytes(), key, nonce, ad.as_bytes());
/// ```
pub fn aead(plain_text: &[u8], key: [u8; 32], nonce: [u8; 24], ad: &[u8]) -> (Vec<u8>, [u8; 16]) {
    unsafe {
        let mut cipher_text: Vec<u8> = vec![0u8; plain_text.len()];
        let mut mac = mem::MaybeUninit::<[u8; 16]>::uninit();
        ffi::crypto_aead_lock(
            cipher_text.as_mut_ptr(),
            mac.as_mut_ptr() as *mut u8,
            key.as_ptr(),
            nonce.as_ptr(),
            ad.as_ptr(),
            ad.len(),
            plain_text.as_ptr(),
            plain_text.len(),
        );
        (cipher_text, mac.assume_init())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn easy_aead() {
        let plaintext = "secret";

        let key: [u8; 32] = [1; 32];
        let nonce: [u8; 24] = [2; 24];
        let ad = "data";
        let (a, b) = aead(plaintext.as_bytes(), key, nonce, ad.as_bytes());

        assert_eq!(a, vec![191, 3, 85, 157, 207, 3]);
        assert_eq!(
            b,
            [170, 84, 72, 240, 51, 131, 115, 191, 122, 222, 170, 200, 158, 83, 202, 191]
        );
    }
}
