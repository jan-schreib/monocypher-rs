//! Authenticated encryption w/o additional data

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