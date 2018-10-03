//! Chacha20 encryption functions
//!
//! [Official documentation](https://monocypher.org/manual/advanced/chacha20)

use ffi;
use std::mem;

/// Simple encryption function.
///
/// # Example
///
/// ```
/// use monocypher::chacha20::easy;
///
/// easy([42u8; 32], [123u8; 16]);
/// ```
pub fn easy(key: [u8; 32], input: [u8; 16]) -> [u8; 32] {
    unsafe {
        let mut out: [u8; 32] = mem::uninitialized();
        ffi::crypto_chacha20_H(out.as_mut_ptr(), key.as_ptr(), input.as_ptr());
        out
    }
}

pub struct Context(ffi::crypto_chacha_ctx);

/// These functions provide an incremental interface for the Chacha20 encryption primitive.
impl Context {
    #[inline]
    pub fn new(key: &[u8], nonce: [u8; 8]) -> Context {
        unsafe {
            let mut ctx = mem::uninitialized();
            ffi::crypto_chacha20_init(&mut ctx, key.as_ptr(), nonce.as_ptr());
            Context(ctx)
        }
    }

    #[inline]
    pub fn new_x(key: &[u8], nonce: [u8; 24]) -> Context {
        unsafe {
            let mut ctx = mem::uninitialized();
            ffi::crypto_chacha20_x_init(&mut ctx, key.as_ptr(), nonce.as_ptr());
            Context(ctx)
        }
    }

    #[inline]
    pub fn encrypt(&mut self, plain_text: &[u8]) -> Vec<u8> {
        let mut cipher_text = vec![0u8; plain_text.len()];
        unsafe {
            ffi::crypto_chacha20_encrypt(
                &mut self.0,
                cipher_text.as_mut_ptr(),
                plain_text.as_ptr(),
                plain_text.len(),
            );
            cipher_text
        }
    }

    #[inline]
    pub fn decrypt(&mut self, cipher_text: &[u8]) -> Vec<u8> {
        let mut plain_text = vec![0u8; cipher_text.len()];
        unsafe {
            ffi::crypto_chacha20_encrypt(
                &mut self.0,
                plain_text.as_mut_ptr(),
                cipher_text.as_ptr(),
                cipher_text.len(),
            );
            plain_text
        }
    }

    #[inline]
    pub fn stream(&mut self, stream: &mut [u8]) {
        unsafe {
            ffi::crypto_chacha20_stream(&mut self.0, stream.as_mut_ptr(), stream.len());
        }
    }

    #[inline]
    pub fn chacha20_set_ctr(&mut self, ctr: u64) {
        unsafe {
            ffi::crypto_chacha20_set_ctr(&mut self.0, ctr);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn new() {
        let key: [u8; 32] = [
            171, 107, 219, 186, 0, 173, 209, 50, 252, 77, 93, 85, 99, 106, 222, 162, 122, 140, 150,
            228, 61, 93, 186, 251, 45, 23, 222, 14, 121, 172, 147, 241,
        ];
        let nonce: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 1];

        let mut ctx = Context::new(&key, nonce);
        let mut ctx2 = Context::new(&key, nonce);
        let ciphertext = ctx.encrypt("test".as_bytes());
        let plaintext = ctx2.decrypt(&ciphertext);

        assert_eq!(&plaintext, &"test".as_bytes())
    }

    #[test]
    fn newx() {
        let key: [u8; 32] = [
            171, 107, 219, 186, 0, 173, 209, 50, 252, 77, 93, 85, 99, 106, 222, 162, 122, 140, 150,
            228, 61, 93, 186, 251, 45, 23, 222, 14, 121, 172, 147, 241,
        ];
        let nonce: [u8; 24] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        let mut ctx = Context::new_x(&key, nonce);
        let mut ctx2 = Context::new_x(&key, nonce);
        let ciphertext = ctx.encrypt("test".as_bytes());
        let plaintext = ctx2.decrypt(&ciphertext);

        assert_eq!(&plaintext, &"test".as_bytes())
    }

    #[test]
    fn stream() {
        let key: [u8; 32] = [
            171, 107, 219, 186, 0, 173, 209, 50, 252, 77, 93, 85, 99, 106, 222, 162, 122, 140, 150,
            228, 61, 93, 186, 251, 45, 23, 222, 14, 121, 172, 147, 241,
        ];
        let nonce: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 1];

        let mut ctx = Context::new(&key, nonce);
        let mut v: Vec<u8> = vec![0, 0, 0, 0];
        ctx.stream(& mut v);
        assert_ne!(v, vec![0, 0, 0, 0])
    }

    #[test]
    fn ctx() {
        let key: [u8; 32] = [
            171, 107, 219, 186, 0, 173, 209, 50, 252, 77, 93, 85, 99, 106, 222, 162, 122, 140, 150,
            228, 61, 93, 186, 251, 45, 23, 222, 14, 121, 172, 147, 241,
        ];
        let nonce: [u8; 24] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        let mut ctx = Context::new_x(&key, nonce);
        let mut ctx2 = Context::new_x(&key, nonce);
        let ciphertext = ctx.encrypt("test".as_bytes());
        ctx2.chacha20_set_ctr(1);
        let plaintext = ctx2.decrypt(&ciphertext);

        assert_ne!(&plaintext, &"test".as_bytes())
    }


    #[test]
    fn easy() {
        let res: [u8; 32] = [
            171, 107, 219, 186, 0, 173, 209, 50, 252, 77, 93, 85, 99, 106, 222, 162, 122, 140, 150,
            228, 61, 93, 186, 251, 45, 23, 222, 14, 121, 172, 147, 241,
        ];

        assert_eq!(::chacha20::easy([1u8; 32], [2u8; 16]), res)
    }
}
