//! HChacha20 special purpose hashing function
//!
//! [Official documentation](https://monocypher.org/manual/advanced/h_chacha20)

use std::mem;
use ffi;

/// Not-so-cryptographic hashing function.
/// Use blak2b.
/// 
/// # Example
///
/// ```
/// use monocypher::hashing::hchacha20::easy;
///
/// easy([42u8; 32], [123u8; 16]);
/// ```
pub fn easy(key: [u8; 32], input: [u8; 16]) -> [u8; 32] {
    unsafe {
        let mut out: [u8; 32] = mem::uninitialized();
        ffi::crypto_chacha20_H(out.as_mut_ptr(), key.as_ptr(), input.as_ptr());
        out
    }
}
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn hchacha20() {
        let res: [u8; 32] = [
            171, 107, 219, 186, 0, 173, 209, 50, 252, 77, 93, 85, 99, 106, 222, 162, 122, 140, 150,
            228, 61, 93, 186, 251, 45, 23, 222, 14, 121, 172, 147, 241,
        ];
        assert_eq!(easy([1u8; 32], [2u8; 16]), res)
    }
}