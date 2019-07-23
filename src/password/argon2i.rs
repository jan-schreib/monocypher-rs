//! Argon2i key derivation function
//!
//! [Official documentation](https://monocypher.org/manual/argon2i)

use ffi;
use std::mem;
use libc;
use std::os::raw;

// Allocates the workarea that is used for the argon2i key derivation function.
#[inline]
fn alloc_workarea(size: u32) -> Result<*mut libc::c_void, String> {
    unsafe {
        let work_area: *mut libc::c_void = libc::calloc(1024, size as usize) as *mut libc::c_void;
        if work_area.is_null() {
            return Err("Failed to allocate needed memory.".to_owned());
        }
        Ok(work_area)
    }
}

/// Simple function to derive a key from a password.
///
/// # Example
///
/// ```
/// use monocypher::password::argon2i::easy;
///
/// easy("pass".as_bytes(), "salt".as_bytes(), 100000, 3).unwrap();
/// ```
pub fn easy(
    password: &[u8],
    salt: &[u8],
    nb_blocks: u32,
    nb_iterations: u32,
) -> Result<[u8; 32], String> {
    let work_area = match alloc_workarea(nb_blocks) {
        Ok(wa) => wa,
        Err(e) => return Err(e),
    };

    unsafe {
        let mut hash = mem::MaybeUninit::<[u8; 32]>::uninit();

        ffi::crypto_argon2i(
            hash.as_mut_ptr() as *mut u8,
            hash.assume_init().len() as u32,
            work_area as *mut raw::c_void,
            nb_blocks,
            nb_iterations,
            password.as_ptr(),
            password.len() as u32,
            salt.as_ptr(),
            salt.len() as u32,
        );

        libc::free(work_area);
        Ok(hash.assume_init())
    }
}

/// Function to derive a key from a password with additional data.
///
/// # Example
///
/// ```
/// use monocypher::password::argon2i::general;
///
/// general("pass".as_bytes(), "salt".as_bytes(), 100000, 3, "key".as_bytes(),
///        "ad".as_bytes()).unwrap();
/// ```
pub fn general(
    password: &[u8],
    salt: &[u8],
    nb_blocks: u32,
    nb_iterations: u32,
    key: &[u8],
    ad: &[u8],
) -> Result<[u8; 32], String> {
    let work_area = match alloc_workarea(nb_blocks) {
        Ok(wa) => wa,
        Err(e) => return Err(e),
    };

    unsafe {
        let mut hash = mem::MaybeUninit::<[u8; 32]>::uninit();

        ffi::crypto_argon2i_general(
            hash.as_mut_ptr() as *mut u8,
            hash.assume_init().len() as u32,
            work_area as *mut raw::c_void,
            nb_blocks,
            nb_iterations,
            password.as_ptr(),
            password.len() as u32,
            salt.as_ptr(),
            salt.len() as u32,
            key.as_ptr(),
            key.len() as u32,
            ad.as_ptr(),
            ad.len() as u32,
        );

        libc::free(work_area);
        Ok(hash.assume_init())
    }
}

#[cfg(test)]
mod test {
    use hex;
    use super::*;

    #[test]
    fn argon2i() {
        let pass = hex::encode(easy("pass".as_bytes(), "salt".as_bytes(), 100000, 3).unwrap());
        assert_eq!(
            pass,
            "ddd464eaa16219e5aabec0f7a8bfbd675f1e9ec0663f1b8e8102c7eed2cde478"
        );
    }

    #[test]
    fn argon2i_fail() {
        let pass = hex::encode(easy("pass".as_bytes(), "tlas".as_bytes(), 100000, 3).unwrap());
        assert_ne!(pass, "ddd18e8102c7eed2cde478");
    }

    #[test]
    fn argon2i_general() {
        let pass = hex::encode(
            general(
                "pass".as_bytes(),
                "salt".as_bytes(),
                100000,
                3,
                "key".as_bytes(),
                "ad".as_bytes(),
            ).unwrap(),
        );
        assert_eq!(
            pass,
            "6a49c0b339f0cc721298000f8e4f634fad877d247dae87cd986632a316d17699"
        );
    }

    #[test]
    fn argon2i_general_key_fail() {
        let pass = hex::encode(
            general(
                "pass".as_bytes(),
                "salt".as_bytes(),
                100000,
                3,
                "yek".as_bytes(),
                "ad".as_bytes(),
            ).unwrap(),
        );
        assert_ne!(
            pass,
            "6a49c0b339f0cc721298000f8e4f634fad877d247dae87cd986632a316d17699"
        );
    }

    #[test]
    fn argon2i_general_ad_fail() {
        let pass = hex::encode(
            general(
                "pass".as_bytes(),
                "salt".as_bytes(),
                100000,
                3,
                "key".as_bytes(),
                "da".as_bytes(),
            ).unwrap(),
        );
        assert_ne!(
            pass,
            "6a49c0b339f0cc721298000f8e4f634fad877d247dae87cd986632a316d17699"
        );
    }

    #[test]
    fn workarea_zero() {
        let wa = alloc_workarea(0);
        assert_eq!(wa.is_ok(), true);
        unsafe {
            libc::free(wa.unwrap());
        }
    }
}
