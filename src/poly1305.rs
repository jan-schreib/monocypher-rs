//! Poly1305 one-time message authentication codes

use ffi;
use std::mem;

pub fn easy(message: &[u8], key: [u8; 32]) -> [u8; 16] {
    unsafe {
        let mut mac: [u8; 16] = mem::uninitialized();
        ffi::crypto_poly1305(mac.as_mut_ptr(), message.as_ptr(), message.len(), key.as_ptr());
        mac
    }
}

pub struct Context(ffi::crypto_poly1305_ctx);

impl Context {
    #[inline]
    pub fn new(key: [u8; 32]) -> Context {
        unsafe {
            let mut ctx = mem::uninitialized();
            ffi::crypto_poly1305_init(&mut ctx, key.as_ptr());
            Context(ctx)
        }
    }

    #[inline]
    pub fn update(&mut self, message: &[u8]) {
        unsafe {
            ffi::crypto_poly1305_update(&mut self.0, message.as_ptr(), message.len());
        }
    }

    #[inline]
    pub fn finish(&mut self) -> [u8; 16] {
        unsafe {
            let mut mac: [u8; 16] = mem::uninitialized();
            ffi::crypto_poly1305_final(&mut self.0, mac.as_mut_ptr());
            mac
        }
    }
}

