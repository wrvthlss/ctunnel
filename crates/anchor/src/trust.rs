use std::collections::HashSet;

use crate::PublicKey;

#[derive(Debug, Clone)]
pub enum TrustPolicy {
    // Client: only trust this server key.
    // Server: (not used)
    Pinned(PublicKey),

    // Server: allow only these client keys.
    // Client: (not used)
    AllowList(HashSet<PublicKey>),
}