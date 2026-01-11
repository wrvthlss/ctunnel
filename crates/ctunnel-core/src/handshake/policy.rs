use std::collections::{HashMap, HashSet};
use crate::protocol::Ed25519PublicKey;

// Client policy, which server identity to accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientPolicy {
    pub expected_server: Ed25519PublicKey,
}

// Server-side policy, which client identities to accept.
#[derive(Debug, Clone, PartialEq, Eq)] 
pub struct ServerPolicy {
    pub allowed_clients: HashSet<Ed25519PublicKey>,
}

impl ServerPolicy {
    pub fn new(allowed_clients: HashSet<Ed25519PublicKey>) -> Self {
        Self { allowed_clients }
    }

    pub fn is_allowed(&self, client: &Ed25519PublicKey) -> bool {
        self.allowed_clients.contains(client)
    }
}
