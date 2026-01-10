use ctunnel_core::crypto::{AeadKey, CryptoProvider, Nonce24};
use crate::SodiumCryptoProvider;

#[tokio::test]
async fn random_bytes_changes_buffer() {
    let p = SodiumCryptoProvider::new();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];

    p.random_bytes(&mut a).await.unwrap();
    p.random_bytes(&mut b).await.unwrap();

    assert_ne!(a, [0u8; 32]);
    assert_ne!(b, [0u8; 32]);
    assert_ne!(a, b);
}

#[tokio::test]
async fn ed25519_sign_verify_round_trip() {
    let p = SodiumCryptoProvider::new();
    let kp = p.ed25519_generate().await.unwrap();

    let msg = b"ctunnel ed25519 test";
    let sig = p.ed25519_sign(&kp, msg).await.unwrap();

    p.ed25519_verify(&kp.public, msg, &sig).await.unwrap();

    // mutate message
    let bad_msg = b"ctunnel ed25519 tesU";
    assert!(p.ed25519_verify(&kp.public, bad_msg, &sig).await.is_err());
}

#[tokio::test]
async fn blake2b_32_is_deterministic() {
    let p = SodiumCryptoProvider::new();

    let a = p.blake2b_32(None, b"hello").await.unwrap();
    let b = p.blake2b_32(None, b"hello").await.unwrap();
    let c = p.blake2b_32(None, b"hell0").await.unwrap();

    assert_eq!(a.0, b.0);
    assert_ne!(a.0, c.0);
}

#[tokio::test]
async fn aead_encrypt_decrypt_round_trip_and_tamper() {
    let p = SodiumCryptoProvider::new();

    let key = AeadKey([7u8; 32]);
    let nonce = Nonce24([9u8; 24]);
    let aad = b"header";
    let msg = b"secret payload";

    let c = p.aead_encrypt(&key, &nonce, aad, msg).await.unwrap();
    let m = p.aead_decrypt(&key, &nonce, aad, &c).await.unwrap();
    assert_eq!(m, msg);

    // tamper ciphertext
    let mut tampered = c.clone();
    tampered[0] ^= 0x01;
    assert!(p.aead_decrypt(&key, &nonce, aad, &tampered).await.is_err());

    // tamper aad
    assert!(p.aead_decrypt(&key, &nonce, b"HEADER", &c).await.is_err());
}