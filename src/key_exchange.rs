use ffi;
use std::mem;

pub fn key_exchange(secret_key: [u8; 32], their_public_key: [u8; 32]) -> Result<[u8; 32], String>{
    unsafe {
        let mut shared_key: [u8; 32] = mem::uninitialized();
        if ffi::crypto_key_exchange(shared_key.as_mut_ptr(), secret_key.as_ptr(), their_public_key.as_ptr()) == 0 {
            return Ok(shared_key)
        }
        return Err("Their public key is malicious!".to_owned());
    }
}

pub fn key_exchange_public_key(secret_key: [u8; 32]) -> [u8; 32] {
    unsafe {
        let mut public_key: [u8; 32] = mem::uninitialized();
        ffi::crypto_x25519_public_key(public_key.as_mut_ptr(), secret_key.as_ptr());
        public_key
    }
}

