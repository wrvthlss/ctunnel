use crate::{
    crypto::{AeadKey, CryptoProvider, NoncePrefix16, SharedSecret32},
    handshake::{HandshakeError, SessionKeys},
    protocol::Random32,
};

/*
    Derive session keys from shared secret + client/server randoms.
        Design:
            master = BLAKE2b-256(key=shared, data="ctunnel-v1" || client_random || server_random)
            key_c2s = BLAKE2b-256(key=master, data="key_c2s")
            key_s2c = BLAKE2b-256(key=master, data="key_s2c")
            np_c2s  = first16(BLAKE2b-256(key=master, data="np_c2s"))
            np_s2c  = first16(BLAKE2b-256(key=master, data="np_s2c"))
*/
pub async fn derive_session_keys(
    crypto: &dyn CryptoProvider,
    shared: &SharedSecret32,
    client_random: &Random32,
    server_random: &Random32,
) -> Result<SessionKeys, HandshakeError> {
    let mut seed = Vec::with_capacity(b"ctunnel-v1".len() + 32 + 32);
    seed.extend_from_slice(b"ctunnel-v1");
    seed.extend_from_slice(&client_random.0);
    seed.extend_from_slice(&server_random.0);

    let master = crypto
        .blake2b_32(Some(&shared.0), &seed)
        .await
        .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;

    let key_c2s = crypto
        .blake2b_32(Some(&master.0), b"key_c2s")
        .await
        .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;

    let key_s2c = crypto
        .blake2b_32(Some(&master.0), b"key_s2c")
        .await
        .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;

    let np_c2s_h = crypto
        .blake2b_32(Some(&master.0), b"np_c2s")
        .await
        .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;

    let np_s2c_h = crypto
        .blake2b_32(Some(&master.0), b"np_s2c")
        .await
        .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;

    let mut np_c2s = [0u8; 16];
    np_c2s.copy_from_slice(&np_c2s_h.0[..16]);

    let mut np_s2c = [0u8; 16];
    np_s2c.copy_from_slice(&np_s2c_h.0[..16]);

    Ok(SessionKeys {
        key_c2s: AeadKey(key_c2s.0),
        key_s2c: AeadKey(key_s2c.0),
        np_c2s: NoncePrefix16(np_c2s),
        np_s2c: NoncePrefix16(np_s2c),
    })
}