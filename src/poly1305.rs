//! Poly1305 is a one-time message authentication code.
//!
//! [Official documentation](https://monocypher.org/manual/advanced/poly1305)

use ffi;
use std::mem;

/// Produces a message authentication code for the given message and authentication key.
///
/// # Example
///
/// ```
/// use monocypher::poly1305;
///
/// let key = [1u8; 32];
/// let mac = poly1305::auth("test".as_bytes(), key);
///
/// ```
pub fn auth(message: &[u8], key: [u8; 32]) -> [u8; 16] {
    unsafe {
        let mut mac = mem::MaybeUninit::<[u8; 16]>::uninit();
        ffi::crypto_poly1305(
            mac.as_mut_ptr() as *mut u8,
            message.as_ptr(),
            message.len() as u64,
            key.as_ptr(),
        );
        mac.assume_init()
    }
}

pub struct Context(ffi::crypto_poly1305_ctx);

impl Context {
    /// Initializes a new context with the given key.
    #[inline]
    pub fn new(key: [u8; 32]) -> Context {
        unsafe {
            let mut ctx = mem::MaybeUninit::<ffi::crypto_poly1305_ctx>::uninit();
            ffi::crypto_poly1305_init(
                ctx.as_mut_ptr() as *mut ffi::crypto_poly1305_ctx,
                key.as_ptr(),
            );
            Context(ctx.assume_init())
        }
    }

    /// Authenticates the message chunk by chunk.
    #[inline]
    pub fn update(&mut self, message: &[u8]) {
        unsafe {
            ffi::crypto_poly1305_update(&mut self.0, message.as_ptr(), message.len() as u64);
        }
    }

    /// Produces the message authentication code.
    #[inline]
    pub fn finalize(&mut self) -> [u8; 16] {
        unsafe {
            let mut mac = mem::MaybeUninit::<[u8; 16]>::uninit();
            ffi::crypto_poly1305_final(&mut self.0, mac.as_mut_ptr() as *mut u8);
            mac.assume_init()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn auth() {
        let key = [1u8; 32];
        let mac = ::poly1305::auth("test".as_bytes(), key);
        assert_eq!(
            mac,
            [20, 62, 33, 196, 79, 94, 80, 79, 78, 94, 80, 79, 78, 94, 80, 79]
        )
    }

    #[test]
    fn ctx() {
        let key = [2u8; 32];
        let mut ctx = Context::new(key);
        ctx.update("test".as_bytes());
        let mac = ctx.finalize();

        assert_eq!(
            mac,
            [40, 124, 66, 136, 159, 188, 160, 158, 156, 188, 160, 158, 156, 188, 160, 158]
        )
    }
}
