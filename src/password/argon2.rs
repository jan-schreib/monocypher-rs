//! Argon2i key derivation function
//!
//! [Official documentation](https://monocypher.org/manual/argon2)

use ffi;
use libc::{self};
use std::mem;
use std::os::raw;

// Allocates the workarea that is used for the argon2i key derivation function.
#[inline]
fn alloc_workarea(size: u32) -> Result<*mut libc::c_void, String> {
    unsafe {
        let work_area: *mut libc::c_void = libc::calloc(1024, size as usize);
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
/// use monocypher::password::argon2::easy;
///
/// easy("pass".as_bytes(), "salt".as_bytes()).unwrap();
/// ```
pub fn easy(password: &[u8], salt: &[u8]) -> Result<[u8; 32], String> {
    unsafe {
        let config = ffi::crypto_argon2_config {
            algorithm: ffi::CRYPTO_ARGON2_I,
            nb_blocks: 100000,
            nb_passes: 3,
            nb_lanes: 1,
        };

        let inputs = ffi::crypto_argon2_inputs {
            pass: password.as_ptr(),
            salt: salt.as_ptr(),
            pass_size: password.len() as u32,
            salt_size: salt.len() as u32,
        };

        let extras = ffi::crypto_argon2_extras {
            key: std::ptr::null(),
            ad: std::ptr::null(),
            key_size: 0,
            ad_size: 0,
        };

        let work_area = match alloc_workarea(100000) {
            Ok(wa) => wa,
            Err(e) => return Err(e),
        };

        let mut hash = mem::MaybeUninit::<[u8; 32]>::uninit();

        ffi::crypto_argon2(
            hash.as_mut_ptr() as *mut u8,
            hash.assume_init().len() as u32,
            work_area as *mut raw::c_void,
            config,
            inputs,
            extras,
        );

        libc::free(work_area);
        Ok(hash.assume_init())
    }
}

#[derive(Default, Debug)]
pub enum ArgonAlgorithm {
    #[default]
    Argon2i,
    Argon2d,
    Argon2id,
}

impl From<ArgonAlgorithm> for u32 {
    fn from(algorithm: ArgonAlgorithm) -> Self {
        match algorithm {
            ArgonAlgorithm::Argon2d => 0,
            ArgonAlgorithm::Argon2i => 1,
            ArgonAlgorithm::Argon2id => 2,
        }
    }
}

pub struct Config {
    pub algorithm: ArgonAlgorithm,
    pub blocks: u32,
    pub passes: u32,
    pub lanes: u32,
}

impl From<Config> for ffi::crypto_argon2_config {
    fn from(config: Config) -> Self {
        Self {
            algorithm: config.algorithm.into(),
            nb_blocks: config.blocks,
            nb_passes: config.passes,
            nb_lanes: config.lanes,
        }
    }
}

impl Default for Config {
    // Defaults from https://monocypher.org/manual/argon2
    fn default() -> Self {
        Self {
            algorithm: Default::default(),
            blocks: 100000,
            passes: 3,
            lanes: 1,
        }
    }
}

pub struct Inputs {
    pub password: Vec<u8>,
    pub salt: Vec<u8>,
}

impl From<Inputs> for ffi::crypto_argon2_inputs {
    fn from(inputs: Inputs) -> Self {
        Self {
            pass: inputs.password.as_ptr(),
            salt: inputs.salt.as_ptr(),
            pass_size: inputs.password.len() as u32,
            salt_size: inputs.salt.len() as u32,
        }
    }
}

pub struct Extras {
    pub key: Vec<u8>,
    pub additional_data: Vec<u8>,
}

impl From<Extras> for ffi::crypto_argon2_extras {
    fn from(extras: Extras) -> Self {
        Self {
            key: extras.key.as_ptr(),
            ad: extras.additional_data.as_ptr(),
            key_size: extras.key.len() as u32,
            ad_size: extras.additional_data.len() as u32,
        }
    }
}

/// Function to derive a key from a password with additional data.
///
/// # Example
///
/// ```
/// use monocypher::password::argon2::general;
/// use monocypher::password::argon2::Inputs;
///
/// let inputs = Inputs {
///     password: "pass".as_bytes().into(),
///     salt: "salt".as_bytes().into(),
/// };
///
/// general(Default::default(), inputs, None).unwrap();
/// ```
pub fn general(config: Config, inputs: Inputs, extras: Option<Extras>) -> Result<[u8; 32], String> {
    let work_area = match alloc_workarea(config.blocks) {
        Ok(wa) => wa,
        Err(e) => return Err(e),
    };

    unsafe {
        let mut hash = mem::MaybeUninit::<[u8; 32]>::uninit();

        let extras = if let Some(extras) = extras {
            extras.into()
        } else {
            ffi::crypto_argon2_extras {
                key: std::ptr::null(),
                ad: std::ptr::null(),
                key_size: 0,
                ad_size: 0,
            }
        };

        ffi::crypto_argon2(
            hash.as_mut_ptr() as *mut u8,
            hash.assume_init().len() as u32,
            work_area,
            config.into(),
            inputs.into(),
            extras,
        );

        libc::free(work_area);
        Ok(hash.assume_init())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex;

    #[test]
    fn argon2i() {
        let pass = hex::encode(easy("pass".as_bytes(), "salt".as_bytes()).unwrap());
        assert_eq!(
            pass,
            "ddd464eaa16219e5aabec0f7a8bfbd675f1e9ec0663f1b8e8102c7eed2cde478"
        );
    }

    #[test]
    fn argon2i_fail() {
        let pass = hex::encode(easy("pass".as_bytes(), "tlas".as_bytes()).unwrap());
        assert_ne!(pass, "ddd18e8102c7eed2cde478");
    }

    #[test]
    fn argon2i_general() {
        let inputs = Inputs {
            password: "pass".as_bytes().into(),
            salt: "salt".as_bytes().into(),
        };

        let pass = hex::encode(general(Default::default(), inputs, None).unwrap());
        assert_eq!(
            pass,
            "0a36b76bd9e78f4d9aefa1c79dd15b8ee3c1c71d5034b9696e39dbbc0aade017"
        );
    }

    #[test]
    fn argon2i_general_key_fail() {
        let inputs = Inputs {
            password: "pass".as_bytes().into(),
            salt: "salt".as_bytes().into(),
        };
        let pass = hex::encode(general(Default::default(), inputs, None).unwrap());
        assert_ne!(
            pass,
            "6a49c0b339f0cc721298000f8e4f634fad877d247dae87cd986632a316d17699"
        );
    }

    #[test]
    fn argon2i_general_ad_fail() {
        let inputs = Inputs {
            password: "pass".as_bytes().into(),
            salt: "salt".as_bytes().into(),
        };
        let pass = hex::encode(general(Default::default(), inputs, None).unwrap());
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
