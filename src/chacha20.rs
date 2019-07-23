 //! Chacha20 encryption functions
//!
//! [Official documentation](https://monocypher.org/manual/advanced/chacha20)

use ffi;
use std::mem;

pub struct Context(ffi::crypto_chacha_ctx);

/// These functions provide an incremental interface for the Chacha20 encryption primitive.
///
/// # Example
///
/// ```
/// use monocypher::chacha20::Context;
/// use monocypher::utils::wipe;
///
///    let mut key: [u8; 32] = [
///        171, 107, 219, 186, 0, 173, 209, 50, 252, 77, 93, 85, 99, 106, 222, 162, 122, 140, 150,
///        228, 61, 93, 186, 251, 45, 23, 222, 14, 121, 172, 147, 241,
///    ];
///    let nonce: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 1];
///
///    let mut ctx = Context::new(&key, nonce);
///    let mut ctx2 = Context::new(&key, nonce);
///    let ciphertext = ctx.encrypt("test".as_bytes());
///    let plaintext = ctx2.decrypt(&ciphertext);
///
///    wipe(&mut key);
///
///    assert_eq!(&plaintext, &"test".as_bytes())
/// ```
impl Context {

    /// Initialises a new context with the given key and nonce.
    /// Uses an 8-byte nonce, which is too small to be selected at random.
    /// Use a counter.
    #[inline]
    pub fn new(key: &[u8], nonce: [u8; 8]) -> Context {
        unsafe {
            let mut ctx = mem::MaybeUninit::<ffi::crypto_chacha_ctx>::uninit();
            ffi::crypto_chacha20_init(ctx.as_mut_ptr() as *mut ffi::crypto_chacha_ctx, key.as_ptr(), nonce.as_ptr());
            Context(ctx.assume_init())
        }
    }

    /// Initialises a new context with the given key and nonce.
    /// Uses a 24-byte nonce, which is big enough to be selected at random.
    /// Use your operating system to generate cryptographic secure random numbers.
    /// Read the about random number generators in the [documentation](https://monocypher.org/manual/)
    #[inline]
    pub fn new_x(key: &[u8], nonce: [u8; 24]) -> Context {
        unsafe {
            let mut ctx = mem::MaybeUninit::<ffi::crypto_chacha_ctx>::uninit();
            ffi::crypto_chacha20_x_init(ctx.as_mut_ptr() as *mut ffi::crypto_chacha_ctx, key.as_ptr(), nonce.as_ptr());
            Context(ctx.assume_init())
        }
    }

    /// Encrypts the given plaintext.
    #[inline]
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut cipher_text = vec![0u8; plaintext.len()];
        unsafe {
            ffi::crypto_chacha20_encrypt(
                &mut self.0,
                cipher_text.as_mut_ptr(),
                plaintext.as_ptr(),
                plaintext.len(),
            );
            cipher_text
        }
    }

    /// Decrypts the given ciphertext.
    #[inline]
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        self.encrypt(ciphertext)
    }

    /// Same as encrypt but with plaintext beeing NULL.
    /// Usefull as a non cryptographic user space random number generator.
    #[inline]
    pub fn stream(&mut self, stream: &mut [u8]) {
        unsafe {
            ffi::crypto_chacha20_stream(&mut self.0, stream.as_mut_ptr(), stream.len());
        }
    }

    /// Resets the internal counter of the context to the given number.
    /// Resuming the encryption will use the stream at the block number.
    /// May be used to en/decrypt part of a long message.
    /// Can also be used to implement AEAD constructions like the ones
    /// explained in [RFC 7539](https://tools.ietf.org/html/rfc7539).
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
    fn new_wrong_nonce() {
        let key: [u8; 32] = [
            171, 107, 219, 186, 0, 173, 209, 50, 252, 77, 93, 85, 99, 106, 222, 162, 122, 140, 150,
            228, 61, 93, 186, 251, 45, 23, 222, 14, 121, 172, 147, 241,
        ];

        let nonce: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 1];
        let nonce2: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 8];

        let mut ctx = Context::new(&key, nonce);
        let mut ctx2 = Context::new(&key, nonce2);
        let ciphertext = ctx.encrypt("test".as_bytes());
        let plaintext = ctx2.decrypt(&ciphertext);

        assert_ne!(&plaintext, &"test".as_bytes())
    }

    #[test]
    fn new_x() {
        let key: [u8; 32] = [
            171, 107, 219, 186, 0, 173, 209, 50, 252, 77, 93, 85, 99, 106, 222, 162, 122, 140, 150,
            228, 61, 93, 186, 251, 45, 23, 222, 14, 121, 172, 147, 241,
        ];

        let nonce = [1u8; 24];

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
        let nonce2: [u8; 24] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        let mut ctx = Context::new_x(&key, nonce);
        let mut ctx2 = Context::new_x(&key, nonce2);
        let ciphertext = ctx.encrypt("test".as_bytes());
        ctx2.chacha20_set_ctr(1);
        let plaintext = ctx2.decrypt(&ciphertext);

        assert_ne!(&plaintext, &"test".as_bytes())
    }
}
