use ffi;
use std::os::raw::c_void;
use std::mem;

pub fn verify(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false
    }

    match a.len() {
        16 => unsafe { return ffi::crypto_verify16(a.as_ptr(), b.as_ptr()) == 0 },
        32 => unsafe { return ffi::crypto_verify32(a.as_ptr(), b.as_ptr()) == 0 },
        64 => unsafe { return ffi::crypto_verify64(a.as_ptr(), b.as_ptr()) == 0 },
        _ => return false
    }
}

pub fn wipe(secret: &mut [u8]) {
    unsafe {
        ffi::crypto_wipe(secret.as_mut_ptr() as *mut c_void, secret.len())
    }
}

pub fn lock(key: [u8; 32], nonce: [u8; 24], plain_text: &[u8]) -> (Vec<u8>, [u8; 16]) {
    unsafe {
        let mut cipher_text = vec![0u8; plain_text.len()];
        let mut mac: [u8; 16] = mem::uninitialized();
        ffi::crypto_lock(mac.as_mut_ptr(), cipher_text.as_mut_ptr(),
                         key.as_ptr(), nonce.as_ptr(),
                         plain_text.as_ptr(), plain_text.len());

        (cipher_text, mac)
    }
}

pub fn unlock(key: [u8; 32], nonce: [u8; 24], mac: [u8; 16], cipher_text: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let mut plain_text  = vec![0u8; cipher_text.len()];
        if ffi::crypto_unlock(plain_text.as_mut_ptr(), key.as_ptr(),
                           nonce.as_ptr(), mac.as_ptr(),
                           cipher_text.as_ptr(), cipher_text.len()) == 0 {
            return Ok(plain_text);
        }
        Err("Message is corrupted.".to_owned())
    }
}

pub fn aead_lock(plain_text: &[u8], key: [u8; 32], nonce: [u8; 24], ad: &[u8]) -> (Vec<u8>, [u8; 16]) {
    unsafe {
        let mut cipher_text = vec![0u8; plain_text.len()];
        let mut mac: [u8; 16] = mem::uninitialized();
        ffi::crypto_aead_lock(mac.as_mut_ptr(), cipher_text.as_mut_ptr(),
                              key.as_ptr(), nonce.as_ptr(),
                              ad.as_ptr(), ad.len(),
                              plain_text.as_ptr(), plain_text.len());
        (cipher_text, mac)
    }
}

pub fn aead_unlock(cipher_text: &[u8], key: [u8; 32], nonce: [u8; 24], mac: [u8; 16], ad: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let mut plain_text: Vec<u8> = vec![0u8; cipher_text.len()];
        if ffi::crypto_aead_unlock(plain_text.as_mut_ptr(), key.as_ptr(),
                                   nonce.as_ptr(), mac.as_ptr(),
                                   ad.as_ptr(), ad.len(),
                                   cipher_text.as_ptr(), cipher_text.len()) == 0 {
                return Ok(plain_text)
            }
        Err("Message is corrupted.".to_owned())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn wipe_test() {
        let mut a: [u8; 16] = [0; 16];

        for i in 0..a.len() {
            a[i] = i as u8;
        }

        for i in 0..a.len() {
            assert_eq!(a[i], i as u8);
        }

        wipe(&mut a);

        for i in 0..a.len() {
            assert_eq!(a[i], 0);
        }
    }

    #[test]
    fn verify_len_test() {
        let a = [4; 16];
        let b = [4; 32];
        assert_eq!(verify(&a, &b), false)
    }

    #[test]
    fn verify16_test() {
        let a = [1u8; 16];
        let b = [1u8; 16];

        assert!(verify(&a, &b))
    }

    #[test]
    fn verify16_fail_test() {
        let a = [1u8; 16];
        let b = [3u8; 16];

        assert_eq!(verify(&a, &b), false)
    }

    #[test]
    fn verify32_test() {
        let a = [1u8; 32];
        let b = [1u8; 32];

        assert!(verify(&a, &b))
    }

    #[test]
    fn verify32_fail_test() {
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
    fn verify64_fail_test() {
        let a = [1u8; 64];
        let b = [3u8; 64];

        assert_eq!(verify(&a, &b), false)
    }
}