use ctunnel_core::crypto::{
    AeadKey, CryptoError, Ed25519Keypair, Hash32, Nonce24, SharedSecret32, Signature64, X25519Keypair,
};

use super::ffi;

pub(crate) fn sodium_init() -> Result<(), CryptoError> {
    let rc = ffi::sodium_init();
    if rc < 0 {
        return Err(CryptoError::RngFailure);
    }
    Ok(())
}

pub(crate) fn random_bytes(out: &mut [u8]) -> Result<(), CryptoError> {
    if out.is_empty() {
        return Ok(());
    }
    ffi::randombytes_buf(out.as_mut_ptr(), out.len());
    Ok(())
}

// --- Ed25519 ---
pub(crate) fn ed25519_generate() -> Result<Ed25519Keypair, CryptoError> {
    let mut pk = [0u8; 32];
    let mut sk = [0u8; 64];

    let rc = ffi::ed25519_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
    if rc != 0 {
        return Err(CryptoError::InvalidKey);
    }

    Ok(Ed25519Keypair { public: pk, secret: sk })
}

pub(crate) fn ed25519_sign(keypair: &Ed25519Keypair, msg: &[u8]) -> Result<Signature64, CryptoError> {
    let mut sig = [0u8; 64];
    let mut siglen: u64 = 0;

    let rc = ffi::ed25519_sign_detached(
        sig.as_mut_ptr(),
        &mut siglen as *mut u64 as *mut _,
        msg.as_ptr(),
        msg.len() as u64,
        keypair.secret.as_ptr(),
    );

    if rc != 0 || siglen != 64 {
        return Err(CryptoError::EncryptFailure);
    }

    Ok(Signature64(sig))
}

pub(crate) fn ed25519_verify(public: &[u8; 32], msg: &[u8], sig: &Signature64) -> Result<(), CryptoError> {
    let rc = ffi::ed25519_verify_detached(sig.0.as_ptr(), msg.as_ptr(), msg.len() as u64, public.as_ptr());
    if rc != 0 {
        return Err(CryptoError::BadSignature);
    }
    Ok(())
}

// --- X25519 ---
//  - MVP will generate secrets via randombytes and derive the public using scalarmult_base later.

pub(crate) fn x25519_generate() -> Result<X25519Keypair, CryptoError> {
    Err(CryptoError::InvalidKey)
}

pub(crate) fn x25519_shared_secret(my_secret: &[u8; 32], peer_public: &[u8; 32]) -> Result<SharedSecret32, CryptoError> {
    let mut shared = [0u8; 32];
    let rc = ffi::x25519_scalarmult(shared.as_mut_ptr(), my_secret.as_ptr(), peer_public.as_ptr());
    if rc != 0 {
        return Err(CryptoError::KeyAgreementFailure);
    }
    Ok(SharedSecret32(shared))
}

// --- BLAKE2b (generichash) ---
pub(crate) fn blake2b_32(key: Option<&[u8]>, data: &[u8]) -> Result<Hash32, CryptoError> {
    let mut out = [0u8; 32];

    let (kptr, klen) = if let Some(k) = key {
        (k.as_ptr(), k.len())
    } else {
        (std::ptr::null(), 0usize)
    };

    let rc = ffi::generichash(out.as_mut_ptr(), out.len(), data.as_ptr(), data.len() as u64, kptr, klen);
    if rc != 0 {
        return Err(CryptoError::HashFailure);
    }

    Ok(Hash32(out))
}

// --- AEAD XChaCha20-Poly1305 IETF ---
pub(crate) fn aead_encrypt(
    key: &AeadKey,
    nonce: &Nonce24,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // ciphertext length = plaintext + 16-byte tag
    let mut c = vec![0u8; plaintext.len() + 16];
    let mut clen: u64 = 0;

    let rc = ffi::aead_xchacha20poly1305_ietf_encrypt(
        c.as_mut_ptr(),
        &mut clen as *mut u64 as *mut _,
        plaintext.as_ptr(),
        plaintext.len() as u64,
        aad.as_ptr(),
        aad.len() as u64,
        std::ptr::null(),
        nonce.0.as_ptr(),
        key.0.as_ptr(),
    );

    if rc != 0 {
        return Err(CryptoError::EncryptFailure);
    }

    c.truncate(clen as usize);
    Ok(c)
}

pub(crate) fn aead_decrypt(
    key: &AeadKey,
    nonce: &Nonce24,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // plaintext length <= ciphertext (ciphertext includes tag)
    let mut m = vec![0u8; ciphertext.len()];
    let mut mlen: u64 = 0;

    let rc = ffi::aead_xchacha20poly1305_ietf_decrypt(
        m.as_mut_ptr(),
        &mut mlen as *mut u64 as *mut _,
        std::ptr::null_mut(),
        ciphertext.as_ptr(),
        ciphertext.len() as u64,
        aad.as_ptr(),
        aad.len() as u64,
        nonce.0.as_ptr(),
        key.0.as_ptr(),
    );

    if rc != 0 {
        return Err(CryptoError::DecryptFailure);
    }

    m.truncate(mlen as usize);
    Ok(m)
}