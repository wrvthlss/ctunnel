use crate::protocol::{MSG_CLIENT_HELLO, MSG_CLIENT_FINISH, MSG_SERVER_HELLO, PROTOCOL_VERSION_V1};

#[test]
fn protocol_constants_are_stable() {
    assert_eq!(PROTOCOL_VERSION_V1, 0x0001);
    assert_eq!(MSG_CLIENT_HELLO, 0x01);
    assert_eq!(MSG_SERVER_HELLO, 0x02);
    assert_eq!(MSG_CLIENT_FINISH, 0x03);
}

#[test]
fn size_assumptions_hold() {
    use crate::protocol::{Ed25519PublicKey, Random32, Signature64, X25519PublicKey};

    assert_eq!(std::mem::size_of::<Ed25519PublicKey>(), 32);
    assert_eq!(std::mem::size_of::<X25519PublicKey>(), 32);
    assert_eq!(std::mem::size_of::<Random32>(), 32);
    assert_eq!(std::mem::size_of::<Signature64>(), 64);
}
