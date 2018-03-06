//! Authenticated decryption w/o additional data

use ffi;
use std::mem;

///Decrypt encrypted data.
///
///#Example
///```
///use monocypher::lock;
///use monocypher::unlock;
///
///let plaintext = "plaintext";
///let key = [137u8; 32];
///let nonce = [120u8; 24];
///
///let cymac = lock::easy(plaintext.as_bytes(), key, nonce);
///unlock::easy(&cymac.0, key, nonce, cymac.1).unwrap();
///```
pub fn easy(
    cipher_text: &[u8],
    key: [u8; 32],
    nonce: [u8; 24],
    mac: [u8; 16],
) -> Result<Vec<u8>, String> {
    unsafe {
        let mut plain_text: Vec<u8> = vec![0u8; cipher_text.len()];
        if ffi::crypto_unlock(
            plain_text.as_mut_ptr(),
            key.as_ptr(),
            nonce.as_ptr(),
            mac.as_ptr(),
            cipher_text.as_ptr(),
            cipher_text.len(),
        ) == 0
        {
            return Ok(plain_text);
        }
        Err("Message is corrupted.".to_owned())
    }
}

///Decrypt ciphertext with additional data.
///
///#Example
///```
///use monocypher::lock;
///use monocypher::unlock;
///
///let plaintext = "plaintext";
///let key = [137u8; 32];
///let nonce = [120u8; 24];
///let ad = "data";
///
///let cymac = lock::aead(plaintext.as_bytes(), key, nonce, ad.as_bytes());
///unlock::aead(&cymac.0, key, nonce, cymac.1, ad.as_bytes()).unwrap();
///```
pub fn aead(
    cipher_text: &[u8],
    key: [u8; 32],
    nonce: [u8; 24],
    mac: [u8; 16],
    ad: &[u8],
) -> Result<Vec<u8>, String> {
    unsafe {
        let mut plain_text: Vec<u8> = vec![0u8; cipher_text.len()];
        if ffi::crypto_unlock_aead(
            plain_text.as_mut_ptr(),
            key.as_ptr(),
            nonce.as_ptr(),
            mac.as_ptr(),
            ad.as_ptr(),
            ad.len(),
            cipher_text.as_ptr(),
            cipher_text.len(),
        ) == 0
        {
            return Ok(plain_text);
        }
        Err("Message is corrupted.".to_owned())
    }
}

pub struct Context(ffi::crypto_lock_ctx);

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
    pub fn auth_message(&mut self, plain_text: &[u8]) {
        unsafe {
            ffi::crypto_lock_auth_message(&mut self.0, plain_text.as_ptr(), plain_text.len());
        }
    }

    #[inline]
    pub fn update(&mut self, cypher_text: &[u8]) -> Vec<u8> {
        unsafe {
            let mut plain_text: Vec<u8> = vec![0u8; cypher_text.len()];
            ffi::crypto_unlock_update(
                &mut self.0,
                plain_text.as_mut_ptr(),
                cypher_text.as_ptr(),
                cypher_text.len(),
            );
            plain_text
        }
    }

    #[inline]
    pub fn finalize(&mut self, mac: [u8; 16]) -> Result<(), String> {
        unsafe {
            if ffi::crypto_unlock_final(&mut self.0, mac.as_ptr()) == 0 {
                return Ok(());
            }
            Err("Message is corrupted.".to_owned())
        }
    }
}
