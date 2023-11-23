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
#[inline]
pub fn verify(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && verify_internal(a, b) == 0
}

#[inline(never)]
fn verify_internal(a: &[u8], b: &[u8]) -> u8 {
    //be paranoid here
    if a.len() != b.len() {
        return 1;
    }
    //"useless", but lets the optimizer skip bounds checks.
    let len = a.len();
    let a = &a[..len];
    let b = &b[..len];

    let cmp = {
        let mut ret = 0;
        for i in 0..len {
            ret |= a[i] ^ b[i]
        }
        ret
    };

    match len {
        16 => cmp,
        32 => cmp,
        64 => cmp,
        _ => 1,
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
    fn verify64() {
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

    #[test]
    fn verify_unsupported_length() {
        let a = [1u8; 1];
        let b = [1u8; 1];

        assert_eq!(verify(&a, &b), false)
    }
}
