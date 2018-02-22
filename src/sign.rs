//! Incremental public key signatures

use ffi;
use std::mem;

pub fn public_key(secret_key: [u8; 32]) -> [u8; 32] {
    unsafe {
        let mut public_key: [u8; 32] = mem::uninitialized();
        ffi::crypto_sign_public_key(public_key.as_mut_ptr(), secret_key.as_ptr());
        public_key
    }
}

pub fn sign(secret_key: [u8; 32], public_key: [u8; 32], message: &[u8]) {
    unsafe {
        let mut signature: [u8; 64] = mem::uninitialized();
        ffi::crypto_sign(signature.as_mut_ptr(), secret_key.as_ptr(), public_key.as_ptr(),
                         message.as_ptr(), message.len() as usize);
    }
}

pub fn check(signature: [u8; 64], public_key: [u8; 32], message: &[u8]) -> Result<(), String> {
    unsafe {
        if ffi::crypto_check(signature.as_ptr(), public_key.as_ptr(),
                             message.as_ptr(), message.len()) == 0 {
            return Ok(());
        }
        return Err("Forged message detected.".to_owned());
    }
}

pub struct Context(ffi::crypto_sign_ctx);

impl Context {
    #[inline]
    pub fn new(secret_key: &str, public_key: &str) -> Context {
        unsafe {
            let mut ctx = mem::uninitialized();
            ffi::crypto_sign_init_first_pass(&mut ctx, secret_key.as_ptr(), public_key.as_ptr());
            Context(ctx)
        }
    }

    #[inline]
    pub fn update(&mut self, message: &[u8]) {
        unsafe {
            ffi::crypto_sign_update(&mut self.0, message.as_ptr(), message.len());
        }
    }

    #[inline]
    pub fn finish(&mut self) -> [u8; 64] {
        unsafe {
            let mut signature: [u8; 64] = mem::uninitialized();
            ffi::crypto_sign_final(&mut self.0, signature.as_mut_ptr());
            signature
        }
    }

    #[inline]
    pub fn init_second_pass(&mut self) {
        unsafe {
            ffi::crypto_sign_init_second_pass(&mut self.0);
        }
    }
}