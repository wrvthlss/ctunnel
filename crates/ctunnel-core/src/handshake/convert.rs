use crate::{crypto, protocol};

pub fn proto_sig_to_crypto(sig: protocol::Signature64) -> crypto::Signature64 {
    crypto::Signature64(sig.0)
}

pub fn crypto_sig_to_proto(sig: crypto::Signature64) -> protocol::Signature64 {
    protocol::Signature64(sig.0)
}