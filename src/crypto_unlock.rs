use ffi;
use std::mem;

pub struct CryptoUnlockCtx(ffi::crypto_unlock_ctx);

impl CryptoUnlockCtx {
    #[inline]
    pub fn new(key: [u8; 32], nonce: [u8; 24]) -> CryptoUnlockCtx {
        unsafe {
            let mut ctx = mem::uninitialized();
            ffi::crypto_unlock_init(&mut ctx, key.as_ptr(), nonce.as_ptr());
            CryptoUnlockCtx(ctx)
        }
    }

    #[inline]
    pub fn auth_ad(&mut self, ad: &[u8]) {
        unsafe {
            ffi::crypto_unlock_auth_ad(&mut self.0, ad.as_ptr(), ad.len());
        }
    }

    #[inline]
    pub fn auth_message(&mut self, plain_text: &[u8]) {
        unsafe {
            ffi::crypto_unlock_auth_message(&mut self.0, plain_text.as_ptr(), plain_text.len());
        }
    }

    #[inline]
    pub fn update(&mut self, cypher_text: &[u8]) -> Vec<u8> {
        unsafe {
            let mut plain_text: Vec<u8> = vec![0u8; cypher_text.len()];
            ffi::crypto_unlock_update(&mut self.0, plain_text.as_mut_ptr(),
                                      cypher_text.as_ptr(), cypher_text.len());
            plain_text
        }
    }

    #[inline]
    pub fn finish(&mut self, mac: [u8; 16]) ->  Result<(), String> {
        unsafe {
            if ffi::crypto_unlock_final(&mut self.0, mac.as_ptr()) == 0 {
                Ok(())
            }
            Err("Message is corrupted.".to_owned())
        }
    }
}