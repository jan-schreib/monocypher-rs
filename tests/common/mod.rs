use monocypher::aead::*;

pub fn enc_setup(key: [u8; 32], nonce: [u8; 24]) -> (Vec<u8>, [u8; 16]) {
    let plaintext = "secret";

    lock::easy(plaintext.as_bytes(), key, nonce)
}

pub fn aead_enc_setup(key: [u8; 32], nonce: [u8; 24], ad: &str) -> (Vec<u8>, [u8; 16]) {
    let plaintext = "secret";

    lock::aead(plaintext.as_bytes(), key, nonce, ad.as_bytes())
}