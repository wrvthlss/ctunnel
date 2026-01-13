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
    return hdr + payload  # keep original prefix

def parse_payload(frame: bytes) -> bytes:
    ln = struct.unpack(">I", frame[:4])[0]
    return frame[4:4+ln]

def payload_type(payload: bytes):
    return payload[0] if payload else None

def tamper_server_hello_sig(frame: bytes) -> bytes:
    """
    ServerHello wire payload layout:
      [type=0x02][version u16][flags u8]
      [server_id_pk 32]
      [server_eph_pk 32]
      [server_random 32]
      [server_sig 64]
    Total payload len: 164
    Signature offset in payload: 1+2+1+32+32+32 = 100
    So signature bytes are payload[100:164]
    We'll flip one bit in payload[100].
    """
    hdr = frame[:4]
    payload = bytearray(parse_payload(frame))

    if len(payload) != 164 or payload_type(payload) != 0x02:
        return frame

    sig_off = 100
    payload[sig_off] ^= 0x01  # flip 1 bit
    return hdr + bytes(payload)

def forward(src: socket.socket, dst: socket.socket, direction: str, mode: str, stop_evt: threading.Event):
    try:
        while not stop_evt.is_set():
            frame = read_frame(src)
            payload = parse_payload(frame)
            t = payload_type(payload)

            # Only tamper server->client ServerHello if mode set
            if direction == "s2c" and mode == "tamper_serverhello_sig" and t == 0x02:
                print("[tamper] modifying ServerHello signature byte")
                frame = tamper_server_hello_sig(frame)

            dst.sendall(frame)
    except (EOFError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        print("[tamper] exception:", e)
    finally:
        stop_evt.set()
        try: dst.shutdown(socket.SHUT_RDWR)
        except Exception: pass
        try: src.shutdown(socket.SHUT_RDWR)
        except Exception: pass
        src.close()
        dst.close()

def main():
    ap = argparse.ArgumentParser(description="MITM TCP proxy that can tamper ctunnel handshake frames.")
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, required=True, help="Proxy listen port (client connects here)")
    ap.add_argument("--upstream-host", default="127.0.0.1")
    ap.add_argument("--upstream-port", type=int, required=True, help="Upstream server port")
    ap.add_argument("--mode", choices=["tamper_serverhello_sig"], default="tamper_serverhello_sig")
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