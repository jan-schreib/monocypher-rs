//! Poly1305 one-time message authentication codes
//! Poly1305 is a one-time message authentication code.
//! "One-time" means the authentication key can be used only once.

use ffi;
use std::mem;

///Produces a message authentication code for the given message and authentication key.
pub fn auth(message: &[u8], key: [u8; 32]) -> [u8; 16] {
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
    pub fn finalize(&mut self) -> [u8; 16] {
        unsafe {
            let mut mac: [u8; 16] = mem::uninitialized();
            ffi::crypto_poly1305_final(&mut self.0, mac.as_mut_ptr());
            mac
        }
    }
}

