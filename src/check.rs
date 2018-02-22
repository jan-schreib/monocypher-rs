//! Public key signature functions

use ffi;
use std::mem;

pub struct Context(ffi::crypto_check_ctx);

impl Context {
    #[inline]
    pub fn new(signature: [u8; 64], public_key: [u8; 32]) -> Context {
        unsafe {
            let mut ctx = mem::uninitialized();
            ffi::crypto_check_init(&mut ctx, signature.as_ptr(), public_key.as_ptr());
            Context(ctx)
        }
    }

    #[inline]
    pub fn update(&mut self, message: &[u8]) {
        unsafe {
            ffi::crypto_check_update(&mut self.0, message.as_ptr(), message.len());
        }
    }

    #[inline]
    pub fn finish(&mut self) -> Result<(), String> {
        unsafe {
            if ffi::crypto_check_final(&mut self.0) == 0 {
                return Ok(())
            }
            return Err("Message corrupted, aborting.".to_owned())
        }
    }
}