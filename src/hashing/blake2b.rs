//! Blake2b hash function
//!
//! [Official documentation](https://monocypher.org/manual/hash)

use ffi;
use std::mem;

/// Simple function to hash the input data.
///
/// # Example
///
/// ```
/// use monocypher::hashing::blake2b::easy;
///
/// let hash = easy("tohash".as_bytes());
/// ```
pub fn easy(data: &[u8]) -> [u8; 64] {
    general(data, b"")
}

/// Function to hash the input data with an additional key.
///
/// # Example
///
/// ```
/// use monocypher::hashing::blake2b::general;
///
/// let hash = general("tohash".as_bytes(), "key".as_bytes());
/// ```
pub fn general(data: &[u8], key: &[u8]) -> [u8; 64] {
    unsafe {
        let mut hash = mem::MaybeUninit::<[u8; 64]>::uninit();
        ffi::crypto_blake2b_general(
            hash.as_mut_ptr() as *mut u8,
            64,
            key.as_ptr(),
            key.len(),
            data.as_ptr(),
            data.len(),
        );
        hash.assume_init()
    }
}

pub struct Context(ffi::crypto_blake2b_ctx);

/// Context based hashing for e.g. large inputs.
///
/// # Example
///
/// ```
/// use monocypher::hashing::blake2b::Context;
///
/// let mut ctx = Context::new("tohash".as_bytes());
/// ctx.update("moretohash".as_bytes());
/// let hash = ctx.finalize();
/// ```
impl Context {
    #[inline]

    /// Initializes a new context with the given key.
    pub fn new(key: &[u8]) -> Context {
        unsafe {
            let mut ctx = mem::MaybeUninit::<ffi::crypto_blake2b_ctx>::uninit();
            ffi::crypto_blake2b_general_init(
                ctx.as_mut_ptr(),
                64,
                key.as_ptr(),
                key.len(),
            );
            Context(ctx.assume_init())
        }
    }

    /// Updates the context with the given data.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            ffi::crypto_blake2b_update(&mut self.0, data.as_ptr(), data.len());
        }
    }

    /// Finalizes the hash and returns it.
    #[inline]
    pub fn finalize(&mut self) -> [u8; 64] {
        unsafe {
            let mut hash = mem::MaybeUninit::<[u8; 64]>::uninit();
            ffi::crypto_blake2b_final(&mut self.0, hash.as_mut_ptr() as *mut u8);
            hash.assume_init()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex;

    #[test]
    fn blake2b_incremental() {
        let mut ctx = Context::new("test".as_bytes());
        ctx.update("TEST".as_bytes());
        let hash = ctx.finalize();
        assert_eq!(hex::encode(hash.to_vec()), "e33ee689585ebe3fc169a845482a47432c21a4134134d2f6c57d06dda4622500e73c79f3ab9d8a3728a7575ebb0f5a78bc6608db427e18cbba1ff6847e3fb6bb");
    }

    #[test]
    fn blake2b_len() {
        let vec = easy("TEST".as_bytes());
        assert_eq!(vec.len(), 64);
    }

    #[test]
    fn blake2b_sum() {
        let ret = easy("TEST".as_bytes()).to_vec();
        assert_eq!(hex::encode(ret), "5322bc39e200a6d2ef54ac6716376d5000f98a9715cb5293edd6e1e0f8865d3b22cb0fa92e09d52abef0cf58a2b067d4bc64fbee1e4bce0e9e642ce803dc6f99");
    }

    #[test]
    fn blake2b_general_len() {
        let vec = general("TEST".as_bytes(), "test".as_bytes());
        assert_eq!(vec.len(), 64);
    }

    #[test]
    fn blake2b_general_sum() {
        let ret = general("TEST".as_bytes(), "test".as_bytes()).to_vec();
        assert_eq!(hex::encode(ret), "e33ee689585ebe3fc169a845482a47432c21a4134134d2f6c57d06dda4622500e73c79f3ab9d8a3728a7575ebb0f5a78bc6608db427e18cbba1ff6847e3fb6bb");
    }
}
