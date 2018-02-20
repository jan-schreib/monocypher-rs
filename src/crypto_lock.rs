//! Authenticated encryption w/o additional data, constant time verification
//! and memory wipe functions.

use ffi;
use std::mem;

///Encrypt and authenticate plaintext data.
///
///#Example
///```
///use monocypher::crypto_lock::lock;
///
///let plaintext = "plaintext";
///let key = [137u8; 32];
///let nonce = [120u8; 24];
///
///let cymac = lock(plaintext.as_bytes(), key, nonce);
///```
pub fn lock(plain_text: &[u8], key: [u8; 32], nonce: [u8; 24]) -> (Vec<u8>, [u8; 16]) {
    unsafe {
        let mut cipher_text: Vec<u8>  = vec![0u8; plain_text.len()];
        let mut mac: [u8; 16] = mem::uninitialized();
        ffi::crypto_lock(mac.as_mut_ptr(), cipher_text.as_mut_ptr(),
                         key.as_ptr(), nonce.as_ptr(),
                         plain_text.as_ptr(), plain_text.len());

        (cipher_text, mac)
    }
}

///Decrypt encrypted data.
///
///#Example
///```
///use monocypher::crypto_lock::{lock, unlock};
///
///let plaintext = "plaintext";
///let key = [137u8; 32];
///let nonce = [120u8; 24];
///
///let cymac = lock(plaintext.as_bytes(), key, nonce);
///unlock(&cymac.0, key, nonce, cymac.1).unwrap();
///```
pub fn unlock(cipher_text: &[u8], key: [u8; 32], nonce: [u8; 24], mac: [u8; 16]) -> Result<Vec<u8>, String> {
    unsafe {
        let mut plain_text: Vec<u8>  = vec![0u8; cipher_text.len()];
        if ffi::crypto_unlock(plain_text.as_mut_ptr(), key.as_ptr(),
                           nonce.as_ptr(), mac.as_ptr(),
                           cipher_text.as_ptr(), cipher_text.len()) == 0 {
            return Ok(plain_text);
        }
        Err("Message is corrupted.".to_owned())
    }
}

pub struct CryptoLockCtx(ffi::crypto_lock_ctx);

impl CryptoLockCtx {
    #[inline]
    pub fn new(key: [u8; 32], nonce: [u8; 24]) -> CryptoLockCtx {
        unsafe {
            let mut ctx = mem::uninitialized();
            ffi::crypto_lock_init(&mut ctx, key.as_ptr(), nonce.as_ptr());
            CryptoLockCtx(ctx)
        }
    }

    #[inline]
    pub fn auth_ad(&mut self, ad: &[u8]) {
        unsafe {
            ffi::crypto_lock_auth_ad(&mut self.0, ad.as_ptr(), ad.len());
        }
    }

    #[inline]
    pub fn auth_message(&mut self, plain_text: &[u8]) {
        unsafe {
            ffi::crypto_lock_auth_message(&mut self.0, plain_text.as_ptr(), plain_text.len());
        }
    }

    #[inline]
    pub fn update(&mut self, plaint_text: &[u8]) -> Vec<u8> {
        unsafe {
            let mut cypher_text: Vec<u8> = vec![0u8; plaint_text.len()];
            ffi::crypto_lock_update(&mut self.0, cypher_text.as_mut_ptr(),
                                    plaint_text.as_ptr(), plaint_text.len());
            cypher_text
        }
    }

    #[inline]
    pub fn finish(&mut self) -> [u8; 16] {
        unsafe {
            let mut mac: [u8; 16] = mem::uninitialized();
            ffi::crypto_lock_final(&mut self.0, mac.as_mut_ptr());
            mac
        }
    }
}



///Encrypt and authenticate plaintext with additional data.
///
///#Example
///```
///use monocypher::crypto_lock::aead_lock;
///
///let plaintext = "plaintext";
///let key = [137u8; 32];
///let nonce = [120u8; 24];
///let ad = "data";
///
///let cymac = aead_lock(plaintext.as_bytes(), key, nonce, ad.as_bytes());
///```
pub fn aead_lock(plain_text: &[u8], key: [u8; 32], nonce: [u8; 24], ad: &[u8]) -> (Vec<u8>, [u8; 16]) {
    unsafe {
        let mut cipher_text: Vec<u8> = vec![0u8; plain_text.len()];
        let mut mac: [u8; 16] = mem::uninitialized();
        ffi::crypto_lock_aead(mac.as_mut_ptr(), cipher_text.as_mut_ptr(),
                              key.as_ptr(), nonce.as_ptr(),
                              ad.as_ptr(), ad.len(),
                              plain_text.as_ptr(), plain_text.len());
        (cipher_text, mac)
    }
}
///Decrypt ciphertext with additional data.
///
///#Example
///```
///use monocypher::crypto_lock::{aead_lock, aead_unlock};
///
///let plaintext = "plaintext";
///let key = [137u8; 32];
///let nonce = [120u8; 24];
///let ad = "data";
///
///let cymac = aead_lock(plaintext.as_bytes(), key, nonce, ad.as_bytes());
///aead_unlock(&cymac.0, key, nonce, cymac.1, ad.as_bytes()).unwrap();
///```
pub fn aead_unlock(cipher_text: &[u8], key: [u8; 32], nonce: [u8; 24], mac: [u8; 16], ad: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let mut plain_text: Vec<u8> = vec![0u8; cipher_text.len()];
        if ffi::crypto_unlock_aead(plain_text.as_mut_ptr(), key.as_ptr(),
                                   nonce.as_ptr(), mac.as_ptr(),
                                   ad.as_ptr(), ad.len(),
                                   cipher_text.as_ptr(), cipher_text.len()) == 0 {
                return Ok(plain_text)
            }
        Err("Message is corrupted.".to_owned())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn lock_unlock_test() {
        let plaintext = "secret";
        let key: [u8; 32] = [1; 32];
        let nonce: [u8; 24] = [2; 24];

        let cymac = lock(plaintext.as_bytes(), key, nonce);
        let clear = unlock(&cymac.0, key, nonce, cymac.1).unwrap();

        assert_eq!(&String::from_utf8(clear).unwrap(), plaintext)
    }

    #[test]
    fn aead_lock_unlock_test() {
        let plaintext = "secret";
        let ad = "add";
        let key: [u8; 32] = [1; 32];
        let nonce: [u8; 24] = [2; 24];

        let cymac = aead_lock(plaintext.as_bytes(), key, nonce, ad.as_bytes());
        let clear = aead_unlock(&cymac.0, key, nonce, cymac.1, ad.as_bytes()).unwrap();

        assert_eq!(&String::from_utf8(clear).unwrap(), plaintext)
    }


}