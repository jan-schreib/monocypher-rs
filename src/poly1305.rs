//! Poly1305 is a one-time message authentication code.
//! The authentication key can be used only once!
//!
//! [Official documentation](https://monocypher.org/manual/advanced/poly1305)

use ffi;
use std::mem;

/// Produces a message authentication code for the given message and authentication key.
///
/// #Example
pub fn auth(message: &[u8], key: [u8; 32]) -> [u8; 16] {
    unsafe {
        let mut mac: [u8; 16] = mem::uninitialized();
        ffi::crypto_poly1305(
            mac.as_mut_ptr(),
            message.as_ptr(),
            message.len(),
            key.as_ptr(),
        );
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

#[cfg(test)]
mod test {
    use super::*;


    #[test]
    fn auth_test() {
        let key = [1u8; 32];
        let mac = auth("test".as_bytes(), key);
        assert_eq!(mac, [20, 62, 33, 196, 79, 94, 80, 79, 78, 94, 80, 79, 78, 94, 80, 79])
    }

    #[test]
    fn ctx_test() {
        let key = [2u8; 32];
        let mut ctx = Context::new(key);
        ctx.update("test".as_bytes());
        let mac = ctx.finalize();

        assert_eq!(mac,
                   [40, 124, 66, 136, 159, 188, 160, 158, 156, 188, 160, 158, 156, 188, 160, 158])
    }
}