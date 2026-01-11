use crate::protocol::{
    ClientHello, ClientFinish, Ed25519PublicKey, HandshakeMessage, Random32, ServerHello, Signature64,
    X25519PublicKey, PROTOCOL_VERSION_V1, LEN_CLIENT_HELLO, LEN_SERVER_HELLO, LEN_CLIENT_FINISH,
};

#[test]
fn handshake_message_round_trip_client_hello() {
    let msg = HandshakeMessage::ClientHello(ClientHello {
        version: PROTOCOL_VERSION_V1,
        flags: 7,
        client_id_pk: Ed25519PublicKey([1u8; 32]),
        client_eph_pk: X25519PublicKey([2u8; 32]),
        client_random: Random32([3u8; 32]),
    });

    let bytes = msg.encode();
    assert_eq!(bytes.len(), LEN_CLIENT_HELLO);

    let decoded = HandshakeMessage::decode(&bytes).unwrap();
    assert_eq!(decoded, msg);
}

#[test]
fn handshake_message_round_trip_server_hello() {
    let msg = HandshakeMessage::ServerHello(ServerHello {
        version: PROTOCOL_VERSION_V1,
        flags: 0,
        server_id_pk: Ed25519PublicKey([4u8; 32]),
        server_eph_pk: X25519PublicKey([5u8; 32]),
        server_random: Random32([6u8; 32]),
        server_sig: Signature64([7u8; 64]),
    });

    let bytes = msg.encode();
    assert_eq!(bytes.len(), LEN_SERVER_HELLO);

    let decoded = HandshakeMessage::decode(&bytes).unwrap();
    assert_eq!(decoded, msg);
}

#[test]
fn handshake_message_round_trip_client_finish() {
    let msg = HandshakeMessage::ClientFinish(ClientFinish {
        client_sig: Signature64([9u8; 64]),
    });

    let bytes = msg.encode();
    assert_eq!(bytes.len(), LEN_CLIENT_FINISH);

    let decoded = HandshakeMessage::decode(&bytes).unwrap();
    assert_eq!(decoded, msg);
}

#[test]
fn decode_rejects_wrong_length() {
    let bytes = vec![0x01; 10];
    assert!(HandshakeMessage::decode(&bytes).is_err());
}