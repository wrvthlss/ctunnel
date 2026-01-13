use crate::framing::{Frame, FrameLimits, FramingError, LengthPrefixedFrameIo, FrameIo};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn round_trip_single_frame() {
    let (a, b) = io::duplex(4096);

    let mut writer = LengthPrefixedFrameIo::new(a, FrameLimits::DEFAULT);
    let mut reader = LengthPrefixedFrameIo::new(b, FrameLimits::DEFAULT);

    let frame = Frame(b"hello ctunnel".to_vec());

    writer.write_frame(&frame).await.unwrap();
    let got = reader.read_frame().await.unwrap();

    assert_eq!(got, frame);
}

#[tokio::test]
async fn rejects_oversized_frame_length() {
    let (mut a, b) = io::duplex(4096);

    // Send a crafted length prefix that exceeds the receiver's max.
    let mut reader = LengthPrefixedFrameIo::new(
        b,
        FrameLimits {
            max_frame_len: 8,
        },
    );

    let too_big: u32 = 9;
    a.write_all(&too_big.to_be_bytes()).await.unwrap();
    a.write_all(&[0u8; 9]).await.unwrap();
    a.flush().await.unwrap();

    let err = reader.read_frame().await.unwrap_err();
    match err {
        FramingError::FrameTooLarge { len, max } => {
            assert_eq!(len, 9);
            assert_eq!(max, 8);
        }
        other => panic!("expected FrameTooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn unexpected_eof_reading_length() {
    let (mut a, b) = io::duplex(4096);
    let mut reader = LengthPrefixedFrameIo::new(b, FrameLimits::DEFAULT);

    // Write only 2 bytes of the length prefix then drop the writer side.
    a.write_all(&[0, 0]).await.unwrap();
    drop(a);

    let err = reader.read_frame().await.unwrap_err();
    assert!(matches!(err, FramingError::UnexpectedEof));
}

#[tokio::test]
async fn unexpected_eof_reading_payload() {
    let (mut a, b) = io::duplex(4096);
    let mut reader = LengthPrefixedFrameIo::new(b, FrameLimits::DEFAULT);

    // Claim payload is 5 bytes, only send 2 then drop.
    a.write_all(&(5u32.to_be_bytes())).await.unwrap();
    a.write_all(&[1, 2]).await.unwrap();
    drop(a);

    let err = reader.read_frame().await.unwrap_err();
    assert!(matches!(err, FramingError::UnexpectedEof));
}