extern crate monocypher;

use monocypher::crypto_lock;
use monocypher::crypto_unlock;

#[test]
fn lock_unlock_test() {
    let plaintext = "secret";
    let key: [u8; 32] = [1; 32];
    let nonce: [u8; 24] = [2; 24];

    let cymac = crypto_lock::lock(plaintext.as_bytes(), key, nonce);
    let clear = crypto_unlock::unlock(&cymac.0, key, nonce, cymac.1).unwrap();

    assert_eq!(&String::from_utf8(clear).unwrap(), plaintext)
}

#[test]
fn aead_lock_unlock_test() {
    let plaintext = "secret";
    let ad = "add";
    let key: [u8; 32] = [1; 32];
    let nonce: [u8; 24] = [2; 24];

    let cymac = crypto_lock::aead_lock(plaintext.as_bytes(), key, nonce, ad.as_bytes());
    let clear = crypto_unlock::aead_unlock(&cymac.0, key, nonce, cymac.1, ad.as_bytes()).unwrap();

    assert_eq!(&String::from_utf8(clear).unwrap(), plaintext)
}
