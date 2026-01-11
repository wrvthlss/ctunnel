use crate::protocol::{ClientHello, ServerHello};

fn put_u16_be(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64_be(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

// Canonical bytes for ClientHello:
// [type=0x01][version u16][flags u8][client_id_pk 32][client_eph_pk 32][client_random 32]
pub fn client_hello_bytes(ch: &ClientHello) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 2 + 1 + 32 + 32 + 32);
    out.push(0x01);
    put_u16_be(&mut out, ch.version);
    out.push(ch.flags);
    out.extend_from_slice(&ch.client_id_pk.0);
    out.extend_from_slice(&ch.client_eph_pk.0);
    out.extend_from_slice(&ch.client_random.0);
    out
}

// Canonical bytes for ServerHello without signature:
// [type=0x02][version u16][flags u8][server_id_pk 32][server_eph_pk 32][server_random 32]
pub fn server_hello_wo_sig_bytes(sh: &ServerHello) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 2 + 1 + 32 + 32 + 32);
    out.push(0x02);
    put_u16_be(&mut out, sh.version);
    out.push(sh.flags);
    out.extend_from_slice(&sh.server_id_pk.0);
    out.extend_from_slice(&sh.server_eph_pk.0);
    out.extend_from_slice(&sh.server_random.0);
    out
}

// Canonical bytes for ServerHello full:
// (ServerHello_wo_sig_bytes || server_sig 64)
pub fn server_hello_full_bytes(sh: &ServerHello) -> Vec<u8> {
    let mut out = server_hello_wo_sig_bytes(sh);
    out.extend_from_slice(&sh.server_sig.0);
    out
}

// Transcript to be signed by server:
// H( ClientHello_bytes || ServerHello_wo_sig_bytes )
pub fn server_signing_transcript(ch_bytes: &[u8], sh_wo_sig_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ch_bytes.len() + sh_wo_sig_bytes.len());
    out.extend_from_slice(ch_bytes);
    out.extend_from_slice(sh_wo_sig_bytes);
    out
}

// Transcript to be signed by client:
// H( ClientHello_bytes || ServerHello_full_bytes )
pub fn client_signing_transcript(ch_bytes: &[u8], sh_full_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ch_bytes.len() + sh_full_bytes.len());
    out.extend_from_slice(ch_bytes);
    out.extend_from_slice(sh_full_bytes);
    out
}

// AAD for record layer later (not used yet), but we keep a canonical builder here for future.
// [frame_type u8][counter u64 be]
pub fn aad_bytes(frame_type: u8, counter: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8);
    out.push(frame_type);
    put_u64_be(&mut out, counter);
    out
}