//! Authenticated encryption w/o additional data

use ffi;
use std::mem;

/// Encrypt and authenticate plaintext data.
///
/// # Example
///
/// ```
/// use monocypher::aead::lock::easy;
///
/// let plaintext = "plaintext";
/// let key = [137u8; 32];
/// let nonce = [120u8; 24];
///
/// let cymac = easy(plaintext.as_bytes(), key, nonce);
/// ```
pub fn easy(plain_text: &[u8], key: [u8; 32], nonce: [u8; 24]) -> (Vec<u8>, [u8; 16]) {
    unsafe {
        let mut cipher_text: Vec<u8> = vec![0u8; plain_text.len()];
        let mut mac: [u8; 16] = mem::uninitialized();
        ffi::crypto_lock(
            mac.as_mut_ptr(),
            cipher_text.as_mut_ptr(),
            key.as_ptr(),
            nonce.as_ptr(),
            plain_text.as_ptr(),
            plain_text.len(),
        );

        (cipher_text, mac)
    }
}

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
        let mut mac: [u8; 16] = mem::uninitialized();
        ffi::crypto_lock_aead(
            mac.as_mut_ptr(),
            cipher_text.as_mut_ptr(),
            key.as_ptr(),
            nonce.as_ptr(),
            ad.as_ptr(),
            ad.len(),
            plain_text.as_ptr(),
            plain_text.len(),
        );
        (cipher_text, mac)
    }
}

pub struct Context(ffi::crypto_lock_ctx);


/// Incrementally encrypt and authenticate plaintext with additional data.
/// Note: Most users should not need this.
/// # Example
///
/// ```
/// use monocypher::aead::lock::Context;
///
/// let key = [2u8; 32];
/// let nonce = [1u8; 24];
/// let mut ctx = Context::new(key, nonce);
/// ctx.auth_ad("data".as_bytes());
/// let cip = ctx.update("test".as_bytes());
/// let ret = ctx.finalize();
///
/// ```
impl Context {
    #[inline]
    pub fn new(key: [u8; 32], nonce: [u8; 24]) -> Context {
        unsafe {
            let mut ctx = mem::uninitialized();
            ffi::crypto_lock_init(&mut ctx, key.as_ptr(), nonce.as_ptr());
            Context(ctx)
        }
    }

    #[inline]
    pub fn auth_ad(&mut self, ad: &[u8]) {
        unsafe {
            ffi::crypto_lock_auth_ad(&mut self.0, ad.as_ptr(), ad.len());
        }
    }

    #[inline]
    pub fn update(&mut self, plaint_text: &[u8]) -> Vec<u8> {
        unsafe {
            let mut cypher_text: Vec<u8> = vec![0u8; plaint_text.len()];
            ffi::crypto_lock_update(
                &mut self.0,
                cypher_text.as_mut_ptr(),
                plaint_text.as_ptr(),
                plaint_text.len(),
            );
            cypher_text
        }
    }

    #[inline]
    pub fn finalize(&mut self) -> [u8; 16] {
        unsafe {
            let mut mac: [u8; 16] = mem::uninitialized();
            ffi::crypto_lock_final(&mut self.0, mac.as_mut_ptr());
            mac
        }
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
        let (a, b) = easy(plaintext.as_bytes(), key, nonce);

        assert_eq!(a, vec![191, 3, 85, 157, 207, 3]);
        assert_eq!(b, [106, 87, 195, 174, 146, 191, 227, 61, 151, 170, 230, 242, 47, 45, 28, 236]);
    }

    #[test]
    fn ctx() {
        let key = [2u8; 32];
        let nonce = [1u8; 24];

        let mut ctx = Context::new(key, nonce);
        ctx.auth_ad("data".as_bytes());
        let cip = ctx.update("test".as_bytes());
        let ret = ctx.finalize();

        assert_eq!(cip, vec![2, 80, 28, 36]);
        assert_eq!(ret, [242, 64, 42, 164, 160, 49, 172, 240, 33, 52, 132, 23, 171, 222, 221, 253])
    }
}
