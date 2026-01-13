#!/usr/bin/env python3
import argparse
import json
import socket
import struct
import threading
import time
from typing import Optional, Tuple

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
    return hdr + payload  # keep the on-wire framing

def parse_payload_type(frame_bytes: bytes) -> Optional[int]:
    if len(frame_bytes) < 5:
        return None
    ln = struct.unpack(">I", frame_bytes[:4])[0]
    if ln < 1:
        return None
    payload = frame_bytes[4:4+ln]
    return payload[0]

def is_handshake_type(t: Optional[int]) -> bool:
    return t in (0x01, 0x02, 0x03)  # ClientHello, ServerHello, ClientFinish

def forward(src: socket.socket, dst: socket.socket, direction: str, record: list, stop_evt: threading.Event):
    try:
        while not stop_evt.is_set():
            frame = read_frame(src)
            mtype = parse_payload_type(frame)
            # Record only handshake frames
            if is_handshake_type(mtype):
                record.append({
                    "ts": time.time(),
                    "dir": direction,         # "c2s" or "s2c"
                    "type": mtype,            # 0x01/0x02/0x03
                    "frame_hex": frame.hex(), # includes 4-byte len prefix
                })
            dst.sendall(frame)
    except (EOFError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        record.append({"ts": time.time(), "dir": direction, "error": str(e)})
    finally:
        stop_evt.set()
        try: dst.shutdown(socket.SHUT_RDWR)
        except Exception: pass
        try: src.shutdown(socket.SHUT_RDWR)
        except Exception: pass
        src.close()
        dst.close()

def main():
    ap = argparse.ArgumentParser(description="MITM TCP proxy that records ctunnel handshake frames.")
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, required=True, help="Proxy listen port (client connects here)")
    ap.add_argument("--upstream-host", default="127.0.0.1")
    ap.add_argument("--upstream-port", type=int, required=True, help="Upstream server port")
    ap.add_argument("--out", default="handshake_capture.json", help="Output JSON file")
    args = ap.parse_args()

    record = []

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
    t1 = threading.Thread(target=forward, args=(client_sock, upstream, "c2s", record, stop_evt), daemon=True)
    t2 = threading.Thread(target=forward, args=(upstream, client_sock, "s2c", record, stop_evt), daemon=True)
    t1.start()
    t2.start()

    while not stop_evt.is_set():
        time.sleep(0.05)

    ls.close()

    # Write capture
    with open(args.out, "w") as f:
        json.dump(record, f, indent=2)

    # Summary
    counts = {0x01: 0, 0x02: 0, 0x03: 0}
    for r in record:
        if "type" in r and r["type"] in counts:
            counts[r["type"]] += 1
    print(f"[proxy] wrote {args.out}")
    print(f"[proxy] captured: ClientHello={counts[0x01]} ServerHello={counts[0x02]} ClientFinish={counts[0x03]}")

if __name__ == "__main__":
    main()