//! Chacha20 encryption functions

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
        let mut cipher_text = vec![0u8; plain_text.len()];
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

/// HChacha20 special-purpose hashing
pub fn chacha20_h(key: [u8; 32], input: [u8; 16]) -> [u8; 32]{
    unsafe {
        let mut out: [u8; 32] = mem::uninitialized();
        ffi::crypto_chacha20_H(out.as_mut_ptr(), key.as_ptr(), input.as_ptr());
        out
    }
}

mod test {
    use super::chacha20_h;

    #[test]
    fn chacha20_h_test() {
        let res: [u8; 32] = [171, 107, 219, 186,  0, 173, 209,  50,
                             252,  77,  93,  85, 99, 106, 222, 162,
                             122, 140, 150, 228, 61,  93, 186, 251,
                             45,   23, 222, 14, 121, 172, 147, 241];

        assert_eq!(chacha20_h([1u8; 32], [2u8;16]), res)
    }
}
