extern crate monocypher;

mod common;
use monocypher::aead::*;

#[test]
fn aead_lock_unlock() {
    let key: [u8; 32] = [1; 32];
    let nonce: [u8; 24] = [2; 24];
    let ad = "add";
    let plaintext = "secret";

    let cymac = lock::aead(plaintext.as_bytes(), key, nonce, ad.as_bytes());
    let clear = unlock::aead(&cymac.0, key, nonce, cymac.1, ad.as_bytes()).unwrap();

    assert_eq!(&String::from_utf8(clear).unwrap(), "secret")
}

#[test]
fn aead_lock_unlock_mac_corrupt() {
    let key: [u8; 32] = [1; 32];
    let nonce: [u8; 24] = [2; 24];
    let ad = "add";
    let cymac = common::aead_enc_setup(key, nonce, ad);
    let wrong_mac = [1u8; 16];
    let clear = unlock::aead(&cymac.0, key, nonce, wrong_mac, ad.as_bytes());

    assert_eq!(clear.is_err(), true);
    assert_eq!(clear.err().unwrap(), "Message is corrupt.".to_owned())
}
