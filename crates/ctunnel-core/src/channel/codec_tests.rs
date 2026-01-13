use crate::channel::{SecureFrame, ChannelError, FRAME_DATA};
use crate::crypto::Counter;

#[test]
fn secure_frame_round_trip() {
    let f = SecureFrame {
        frame_type: FRAME_DATA,
        counter: Counter(42),
        ciphertext: vec![1, 2, 3, 4, 5],
    };

    let bytes = f.encode();
    let decoded = SecureFrame::decode(&bytes).unwrap();
    assert_eq!(decoded.frame_type, f.frame_type);
    assert_eq!(decoded.counter.0, f.counter.0);
    assert_eq!(decoded.ciphertext, f.ciphertext);
}

#[test]
fn secure_frame_decode_rejects_short() {
    let bytes = vec![0u8; 8];
    let err = SecureFrame::decode(&bytes).unwrap_err();
    assert!(matches!(err, ChannelError::InvalidFrame));
}