//! Util functions for constant time comparison and memory wiping.
//!
//! [Official documentation](https://monocypher.org/manual/wipe)

use ffi;
use std::os::raw::c_void;

/// Constant time comparison of two equal sized buffers.
///
/// The lengths can be 16, 32 or 64. Everything else will return false.
/// If the length or the buffer content differ false will be returned.
///
/// # Example
///
/// ```
/// use monocypher::utils::verify;
///
/// if verify("one".as_bytes(), "one".as_bytes()) {
///     //continue
/// } else {
///     //abort
/// }
/// ```
pub fn verify(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    match a.len() {
        16 => unsafe { ffi::crypto_verify16(a.as_ptr(), b.as_ptr()) == 0 },
        32 => unsafe { ffi::crypto_verify32(a.as_ptr(), b.as_ptr()) == 0 },
        64 => unsafe { ffi::crypto_verify64(a.as_ptr(), b.as_ptr()) == 0 },
        _ => false,
    }
}

/// Clears a memory region.
///
/// # Example
///
/// ```
/// use monocypher::utils::wipe;
///
/// let mut secret: [u8; 16] = [255; 16];
/// wipe(&mut secret);
/// ```
pub fn wipe(secret: &mut [u8]) {
    unsafe { ffi::crypto_wipe(secret.as_mut_ptr() as *mut c_void, secret.len()) }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn wipe() {
        let mut a: [u8; 16] = [0; 16];

        for i in 0..a.len() {
            a[i] = i as u8;
        }

        for i in 0..a.len() {
            assert_eq!(a[i], i as u8);
        }

        ::utils::wipe(&mut a);

        for i in 0..a.len() {
            assert_eq!(a[i], 0);
        }
    }

    #[test]
    fn verify_mix() {
        let a = [4; 16];
        let b = [4; 32];
        assert_eq!(verify(&a, &b), false)
    }

    #[test]
    fn verify16() {
        let a = [1u8; 16];
        let b = [1u8; 16];

        assert!(verify(&a, &b))
    }

    #[test]
    fn verify16_fail() {
        let a = [1u8; 16];
        let b = [3u8; 16];

        assert_eq!(verify(&a, &b), false)
    }

    #[test]
    fn verify32() {
        let a = [1u8; 32];
        let b = [1u8; 32];

        assert!(verify(&a, &b))
    }

    #[test]
    fn verify32_fail() {
        let a = [1u8; 32];
        let b = [3u8; 32];

        assert_eq!(verify(&a, &b), false)
    }

    #[test]
    fn verify64_test() {
        let a = [1u8; 64];
        let b = [1u8; 64];

        assert!(verify(&a, &b))
    }

    #[test]
    fn verify64_fail() {
        let a = [1u8; 64];
        let b = [3u8; 64];

        assert_eq!(verify(&a, &b), false)
    }
}
