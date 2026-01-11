use std::collections::HashSet;

use crate::handshake::{ClientHandshake, ClientPolicy, ServerHandshake, ServerPolicy};
use crate::protocol::Ed25519PublicKey;

#[test]
fn policies_are_constructible_and_comparable() {
    let server_pk = Ed25519PublicKey([1u8; 32]);
    let client_pk = Ed25519PublicKey([2u8; 32]);

    let cp = ClientPolicy {
        expected_server: server_pk,
    };

    let mut allowed = HashSet::new();
    allowed.insert(client_pk);

    let sp = ServerPolicy::new(allowed);

    assert_eq!(cp.expected_server, server_pk);
    assert!(sp.is_allowed(&client_pk));
}

#[test]
fn handshake_state_machines_construct() {
    let server_pk = Ed25519PublicKey([3u8; 32]);
    let client_pk = Ed25519PublicKey([4u8; 32]);

    let client = ClientHandshake::new(ClientPolicy {
        expected_server: server_pk,
    });

    let mut allowed = HashSet::new();
    allowed.insert(client_pk);

    let server = ServerHandshake::new(ServerPolicy::new(allowed));

    // Just proving the types exist and can be constructed.
    assert_eq!(*client.policy(), ClientPolicy { expected_server: server_pk });
    assert!(server.policy().allowed_clients.contains(&client_pk));
}