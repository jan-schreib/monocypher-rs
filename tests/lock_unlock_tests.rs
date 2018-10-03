extern crate monocypher;

use monocypher::aead::*;

#[test]
fn lock_unlock() {
    let plaintext = "secret";
    let key: [u8; 32] = [1; 32];
    let nonce: [u8; 24] = [2; 24];

    let cymac = lock::easy(plaintext.as_bytes(), key, nonce);
    let clear = unlock::easy(&cymac.0, key, nonce, cymac.1).unwrap();

    assert_eq!(&String::from_utf8(clear).unwrap(), plaintext)
}

#[test]
fn lock_unlock_corrupt() {
    let plaintext = "secret";
    let key: [u8; 32] = [1; 32];
    let nonce: [u8; 24] = [2; 24];

    let cymac = lock::easy(plaintext.as_bytes(), key, nonce);
    let wrong_mac = [1u8; 16];
    let clear = unlock::easy(&cymac.0, key, nonce, wrong_mac);

    assert_eq!(clear.is_err(), true);
    assert_eq!(clear.err().unwrap(), "Message is corrupt.".to_owned())
}

#[test]
fn aead_lock_unlock() {
    let plaintext = "secret";
    let ad = "add";
    let key: [u8; 32] = [1; 32];
    let nonce: [u8; 24] = [2; 24];

    let cymac = lock::aead(plaintext.as_bytes(), key, nonce, ad.as_bytes());
    let clear = unlock::aead(&cymac.0, key, nonce, cymac.1, ad.as_bytes()).unwrap();

    assert_eq!(&String::from_utf8(clear).unwrap(), plaintext)
}

#[test]
fn aead_lock_unlock_corrupt() {
    let plaintext = "secret";
    let ad = "add";
    let key: [u8; 32] = [1; 32];
    let nonce: [u8; 24] = [2; 24];

    let cymac = lock::aead(plaintext.as_bytes(), key, nonce, ad.as_bytes());
    let wrong_mac = [1u8; 16];
    let clear = unlock::aead(&cymac.0, key, nonce, wrong_mac, ad.as_bytes());

    assert_eq!(clear.is_err(), true);
    assert_eq!(clear.err().unwrap(), "Message is corrupt.".to_owned())
}
