//! Unsafe FFI calls into libsodium.
//!
//! Policy: This is the only module allowed to use `unsafe` in this crate.

use libsodium_sys as sodium;
use std::os::raw::{c_int, c_uchar, c_ulonglong};

pub(crate) fn sodium_init() -> c_int {
    unsafe { sodium::sodium_init() }
}

pub(crate) fn randombytes_buf(buf: *mut c_uchar, size: usize) {
    unsafe { sodium::randombytes_buf(buf as *mut _, size) }
}

// --- Ed25519 ---
pub(crate) fn ed25519_keypair(pk: *mut c_uchar, sk: *mut c_uchar) -> c_int {
    unsafe { sodium::crypto_sign_keypair(pk as *mut _, sk as *mut _) }
}

pub(crate) fn ed25519_sign_detached(
    sig: *mut c_uchar,
    siglen: *mut c_ulonglong,
    msg: *const c_uchar,
    msglen: c_ulonglong,
    sk: *const c_uchar,
) -> c_int {
    unsafe {
        sodium::crypto_sign_detached(
            sig as *mut _,
            siglen as *mut _,
            msg as *const _,
            msglen,
            sk as *const _,
        )
    }
}

pub(crate) fn ed25519_verify_detached(
    sig: *const c_uchar,
    msg: *const c_uchar,
    msglen: c_ulonglong,
    pk: *const c_uchar,
) -> c_int {
    unsafe { sodium::crypto_sign_verify_detached(sig as *const _, msg as *const _, msglen, pk as *const _) }
}

// --- X25519 scalar mult (shared secret) ---
pub(crate) fn x25519_scalarmult(shared: *mut c_uchar, sk: *const c_uchar, pk: *const c_uchar) -> c_int {
    unsafe { sodium::crypto_scalarmult(shared as *mut _, sk as *const _, pk as *const _) }
}

// --- Generic hash (BLAKE2b) ---
pub(crate) fn generichash(
    out: *mut c_uchar,
    outlen: usize,
    input: *const c_uchar,
    inlen: c_ulonglong,
    key: *const c_uchar,
    keylen: usize,
) -> c_int {
    unsafe { sodium::crypto_generichash(out as *mut _, outlen, input as *const _, inlen, key as *const _, keylen) }
}

// --- AEAD XChaCha20-Poly1305 IETF ---
pub(crate) fn aead_xchacha20poly1305_ietf_encrypt(
    c: *mut c_uchar,
    clen: *mut c_ulonglong,
    m: *const c_uchar,
    mlen: c_ulonglong,
    ad: *const c_uchar,
    adlen: c_ulonglong,
    nsec: *const c_uchar,
    npub: *const c_uchar,
    k: *const c_uchar,
) -> c_int {
    unsafe {
        sodium::crypto_aead_xchacha20poly1305_ietf_encrypt(
            c as *mut _,
            clen as *mut _,
            m as *const _,
            mlen,
            ad as *const _,
            adlen,
            nsec as *const _,
            npub as *const _,
            k as *const _,
        )
    }
}

pub(crate) fn aead_xchacha20poly1305_ietf_decrypt(
    m: *mut c_uchar,
    mlen: *mut c_ulonglong,
    nsec: *mut c_uchar,
    c: *const c_uchar,
    clen: c_ulonglong,
    ad: *const c_uchar,
    adlen: c_ulonglong,
    npub: *const c_uchar,
    k: *const c_uchar,
) -> c_int {
    unsafe {
        sodium::crypto_aead_xchacha20poly1305_ietf_decrypt(
            m as *mut _,
            mlen as *mut _,
            nsec as *mut _,
            c as *const _,
            clen,
            ad as *const _,
            adlen,
            npub as *const _,
            k as *const _,
        )
    }
}