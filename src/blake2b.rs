//! Blake2b hash function

use ffi;
use libc::size_t;
use std::mem;

/// # Example
///
/// ```
/// use monocypher::blake2b::easy;
///
/// let hash = easy("tohash".as_bytes());
/// ```
pub fn easy(data: &[u8]) -> [u8; 64] {
    general(data, b"")
}

/// # Example
///
/// ```
/// use monocypher::blake2b::general;
///
/// let hash = general("tohash".as_bytes(), "key".as_bytes());
/// ```
pub fn general(data: &[u8], key: &[u8]) -> [u8; 64] {
    unsafe {
        let mut hash: [u8; 64] = mem::uninitialized();
        ffi::crypto_blake2b_general(
            hash.as_mut_ptr(),
            64 as size_t,
            key.as_ptr(),
            key.len() as size_t,
            data.as_ptr(),
            data.len() as size_t,
        );
        hash
    }
}

pub struct Context(ffi::crypto_blake2b_ctx);

/// # Example
///
/// ```
/// use monocypher::blake2b::Context;
///
/// let mut ctx = Context::new("tohash".as_bytes());
/// ctx.update("moretohash".as_bytes());
/// let hash = ctx.finalize();
/// ```
impl Context {
    #[inline]
    pub fn new(key: &[u8]) -> Context {
        unsafe {
            let mut ctx = mem::uninitialized();
            ffi::crypto_blake2b_general_init(&mut ctx, 64, key.as_ptr(), key.len());
            Context(ctx)
        }
    }

    #[inline]
    pub fn update(&mut self, buf: &[u8]) {
        unsafe {
            ffi::crypto_blake2b_update(&mut self.0, buf.as_ptr(), buf.len());
        }
    }

    #[inline]
    pub fn finalize(&mut self) -> [u8; 64] {
        unsafe {
            let mut hash: [u8; 64] = mem::uninitialized();
            ffi::crypto_blake2b_final(&mut self.0, hash.as_mut_ptr());
            hash
        }
    }
}

#[cfg(test)]
mod test {
    use hex;
    use super::*;

    #[test]
    fn blake2b_incremental_test() {
        let mut ctx = Context::new("test".as_bytes());
        ctx.update("TEST".as_bytes());
        let hash = ctx.finalize();
        assert_eq!(hex::encode(hash.to_vec()), "e33ee689585ebe3fc169a845482a47432c21a4134134d2f6c57d06dda4622500e73c79f3ab9d8a3728a7575ebb0f5a78bc6608db427e18cbba1ff6847e3fb6bb");
    }

    #[test]
    fn blake2b_len_test() {
        let vec = easy("TEST".as_bytes());
        assert_eq!(vec.len(), 64);
    }

    #[test]
    fn blake2b_sum_test() {
        let ret = easy("TEST".as_bytes()).to_vec();
        assert_eq!(hex::encode(ret), "5322bc39e200a6d2ef54ac6716376d5000f98a9715cb5293edd6e1e0f8865d3b22cb0fa92e09d52abef0cf58a2b067d4bc64fbee1e4bce0e9e642ce803dc6f99");
    }

    #[test]
    fn blake2b_general_len_test() {
        let vec = general("TEST".as_bytes(), "test".as_bytes());
        assert_eq!(vec.len(), 64);
    }

    #[test]
    fn blake2b_general_sum_test() {
        let ret = general("TEST".as_bytes(), "test".as_bytes()).to_vec();
        assert_eq!(hex::encode(ret), "e33ee689585ebe3fc169a845482a47432c21a4134134d2f6c57d06dda4622500e73c79f3ab9d8a3728a7575ebb0f5a78bc6608db427e18cbba1ff6847e3fb6bb");
    }
}
