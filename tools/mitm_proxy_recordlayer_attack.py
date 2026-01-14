#!/usr/bin/env python3
import argparse
import socket
import struct
import threading
import time

# Frame format: [u32 big-endian length][payload...]
def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("socket closed")
        buf += chunk
    return buf

def read_frame(sock: socket.socket) -> bytes:
    hdr = recv_exact(sock, 4)
    (ln,) = struct.unpack(">I", hdr)
    payload = recv_exact(sock, ln)
    return hdr + payload

def parse_payload(frame: bytes) -> bytes:
    ln = struct.unpack(">I", frame[:4])[0]
    return frame[4:4+ln]

def payload_type(payload: bytes):
    return payload[0] if payload else None

def is_handshake(payload: bytes) -> bool:
    t = payload_type(payload)
    return t in (0x01, 0x02, 0x03)

def is_secure_data(payload: bytes) -> bool:
    # SecureFrame layout: [frame_type u8][counter u64][ciphertext...]
    # Demo sends FRAME_DATA = 0x10
    t = payload_type(payload)
    return t == 0x10 and len(payload) >= 9

def tamper_secure_ciphertext(frame: bytes) -> bytes:
    hdr = frame[:4]
    payload = bytearray(parse_payload(frame))

    # payload = [frame_type][counter 8][ciphertext...]
    if not is_secure_data(payload):
        return frame

    # flip a bit in first byte of ciphertext (after 1+8 header)
    ct_off = 9
    if ct_off >= len(payload):
        return frame
    payload[ct_off] ^= 0x01
    return hdr + bytes(payload)

def tamper_secure_header(frame: bytes) -> bytes:
    hdr = frame[:4]
    payload = bytearray(parse_payload(frame))
    if not is_secure_data(payload):
        return frame

    # Flip one bit in counter, counter starts at payload[1..9]
    payload[1] ^= 0x01
    return hdr + bytes(payload)

def forward(src: socket.socket, dst: socket.socket, direction: str, mode: str, stop_evt: threading.Event):
    duplicated = False
    tampered = False

    try:
        while not stop_evt.is_set():
            frame = read_frame(src)
            payload = parse_payload(frame)

            # Only attack *record-layer* frames. Handshake is handled in other scripts.
            if not is_handshake(payload) and is_secure_data(payload) and direction == "c2s":
                if mode == "duplicate_first_data" and not duplicated:
                    print("[attack] duplicating first DATA frame (replay within same session)")
                    dst.sendall(frame)      # original
                    dst.sendall(frame)      # replay
                    duplicated = True
                    continue

                if mode == "tamper_ciphertext" and not tampered:
                    print("[attack] tampering ciphertext of first DATA frame")
                    frame = tamper_secure_ciphertext(frame)
                    tampered = True

                if mode == "tamper_header" and not tampered:
                    print("[attack] tampering header (counter bit flip) of first DATA frame")
                    frame = tamper_secure_header(frame)
                    tampered = True

            dst.sendall(frame)

    except (EOFError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        print("[attack] exception:", e)
    finally:
        stop_evt.set()
        try: dst.shutdown(socket.SHUT_RDWR)
        except Exception: pass
        try: src.shutdown(socket.SHUT_RDWR)
        except Exception: pass
        src.close()
        dst.close()

def main():
    ap = argparse.ArgumentParser(description="MITM TCP proxy for ctunnel record-layer replay/tamper attacks.")
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, required=True, help="Proxy listen port (client connects here)")
    ap.add_argument("--upstream-host", default="127.0.0.1")
    ap.add_argument("--upstream-port", type=int, required=True, help="Upstream server port")
    ap.add_argument("--mode", choices=["duplicate_first_data", "tamper_ciphertext", "tamper_header"], required=True)
    args = ap.parse_args()

    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((args.listen_host, args.listen_port))
    ls.listen(1)

    print(f"[proxy] listening on {args.listen_host}:{args.listen_port} -> {args.upstream_host}:{args.upstream_port}")
    client_sock, client_addr = ls.accept()
    print(f"[proxy] client connected from {client_addr}")

    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream.connect((args.upstream_host, args.upstream_port))
    print("[proxy] connected to upstream")

    stop_evt = threading.Event()
    t1 = threading.Thread(target=forward, args=(client_sock, upstream, "c2s", args.mode, stop_evt), daemon=True)
    t2 = threading.Thread(target=forward, args=(upstream, client_sock, "s2c", args.mode, stop_evt), daemon=True)
    t1.start()
    t2.start()

    while not stop_evt.is_set():
        time.sleep(0.05)

    ls.close()
    print("[proxy] done")

if __name__ == "__main__":
    main()