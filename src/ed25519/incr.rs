//! ED25519 incremental public key signatures
//!
//! [Official documentation](https://monocypher.org/manual/optional/ed25519-incr)

use ffi;
use std::mem;

pub struct SignContext(ffi::crypto_sign_ed25519_ctx);

impl SignContext {
    #[inline]
    pub fn new(secret_key: [u8; 32], public_key: [u8; 32]) -> SignContext {
        unsafe {
            let mut ctx = mem::MaybeUninit::<ffi::crypto_sign_ed25519_ctx>::uninit();
            ffi::crypto_ed25519_sign_init_first_pass(
                ctx.as_mut_ptr() as *mut _ as *mut _,
                secret_key.as_ptr(),
                public_key.as_ptr(),
            );
            SignContext(ctx.assume_init())
        }
    }

    #[inline]
    pub fn update(&mut self, message: &[u8]) {
        unsafe {
            // Can't use the crypto_ed25519_sign_update function alias due to
            // rust-lang/rust-bindgen#258.
            ffi::crypto_sign_update(
                &mut self.0 as *mut _ as *mut _,
                message.as_ptr(),
                message.len() as u64,
            );
        }
    }

    #[inline]
    pub fn finalize(&mut self) -> [u8; 64] {
        unsafe {
            let mut signature = mem::MaybeUninit::<[u8; 64]>::uninit();
            // Can't use the crypto_ed25519_sign_final function alias due to
            // rust-lang/rust-bindgen#258.
            ffi::crypto_sign_final(
                &mut self.0 as *mut _ as *mut _,
                signature.as_mut_ptr() as *mut u8,
            );
            signature.assume_init()
        }
    }

    #[inline]
    pub fn begin_second_pass(&mut self) {
        unsafe {
            // Can't use the crypto_ed25519_sign_init_second_pass function alias due to
            // rust-lang/rust-bindgen#258.
            ffi::crypto_sign_init_second_pass(&mut self.0 as *mut _ as *mut _);
        }
    }
}

pub struct CheckContext(ffi::crypto_check_ed25519_ctx);

impl CheckContext {
    #[inline]
    pub fn new(signature: [u8; 64], public_key: [u8; 32]) -> CheckContext {
        unsafe {
            let mut ctx = mem::MaybeUninit::<ffi::crypto_check_ed25519_ctx>::uninit();
            ffi::crypto_ed25519_check_init(
                ctx.as_mut_ptr() as *mut _ as *mut _,
                signature.as_ptr(),
                public_key.as_ptr(),
            );
            CheckContext(ctx.assume_init())
        }
    }

    #[inline]
    pub fn update(&mut self, message: &[u8]) {
        unsafe {
            // Can't use the crypto_ed25519_check_update function alias due to
            // rust-lang/rust-bindgen#258.
            ffi::crypto_check_update(
                &mut self.0 as *mut _ as *mut _,
                message.as_ptr(),
                message.len() as u64,
            );
        }
    }

    #[inline]
    pub fn finalize(&mut self) -> Result<(), String> {
        unsafe {
            // Can't use the crypto_ed25519_check_final function alias due to
            // rust-lang/rust-bindgen#258.
            if ffi::crypto_check_final(&mut self.0 as *mut _ as *mut _) == 0 {
                return Ok(());
            }
            Err("Message corrupted, aborting.".to_owned())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ed25519;

    #[test]
    fn sign_ctx() {
        let secret_key = [2u8; 32];
        let public_key = ed25519::public_key(secret_key);

        let mut ctx = SignContext::new(secret_key, public_key);

        ctx.update("test".as_bytes());
        ctx.begin_second_pass();
        ctx.update("text".as_bytes());
        let sig = ctx.finalize();

        assert_eq!(
            sig[0..64],
            [
                51, 31, 122, 122, 55, 25, 128, 21, 92, 76, 172, 182, 240, 213, 40, 108, 108, 219,
                11, 163, 70, 48, 118, 93, 44, 189, 251, 26, 172, 202, 182, 82, 180, 94, 216, 29,
                245, 63, 198, 214, 18, 196, 78, 137, 48, 171, 208, 170, 221, 202, 43, 220, 113,
                132, 134, 40, 137, 163, 131, 193, 63, 119, 171, 11,
            ]
        );
    }

    #[test]
    fn check_ctx() {
        let secret_key = [2u8; 32];
        let public_key = ed25519::public_key(secret_key);

        let sig = ed25519::sign(secret_key, public_key, "test".as_bytes());

        let mut ctx = CheckContext::new(sig, public_key);
        ctx.update("test".as_bytes());
        let ret = ctx.finalize();

        assert_eq!(ret.is_ok(), true)
    }

    #[test]
    fn check_ctx_fail() {
        let secret_key = [2u8; 32];
        let public_key = ed25519::public_key(secret_key);

        let sig = ed25519::sign(secret_key, public_key, "test".as_bytes());

        let mut ctx = CheckContext::new(sig, public_key);
        ctx.update("not_test".as_bytes());
        let ret = ctx.finalize();

        assert_eq!(ret.is_err(), true);
        assert_eq!(
            ret.err().unwrap(),
            "Message corrupted, aborting.".to_owned()
        );
    }
}
