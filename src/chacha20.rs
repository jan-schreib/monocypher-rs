use ffi;
use std::mem;

pub struct ChaCha20(ffi::crypto_chacha_ctx);

impl ChaCha20 {

    #[inline]
    pub fn new(key: &[u8], nonce: [u8; 8]) -> ChaCha20 {
        unsafe {
            let mut ctx = mem::uninitialized();
            ffi::crypto_chacha20_init(&mut ctx, key.as_ptr(), nonce.as_ptr());
            ChaCha20(ctx)
        }
    }

    #[inline]
    pub fn new_x(key: &[u8], nonce: [u8; 24]) -> ChaCha20 {
        unsafe {
            let mut ctx = mem::uninitialized();
            ffi::crypto_chacha20_x_init(&mut ctx, key.as_ptr(), nonce.as_ptr());
            ChaCha20(ctx)
        }
    }

    #[inline]
    pub fn encrypt(&mut self, plain_text: &[u8]) -> Vec<u8> {
        let mut cipher_text : Vec<u8> = Vec::with_capacity(plain_text.len());
        unsafe {
            ffi::crypto_chacha20_encrypt(&mut self.0, cipher_text.as_mut_ptr(),
                                         plain_text.as_ptr(), plain_text.len());
        cipher_text
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
