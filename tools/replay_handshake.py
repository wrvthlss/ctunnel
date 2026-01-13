#!/usr/bin/env python3
import argparse
import json
import socket
import struct
from typing import Dict, List

# This replays a previous ClientHello and a
# previous ClientFinish against a fresh server.
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

def send_frame(sock: socket.socket, frame: bytes):
    sock.sendall(frame)

def load_capture(path: str) -> List[Dict]:
    with open(path, "r") as f:
        return json.load(f)

def pick_first(capture: List[Dict], direction: str, msg_type: int) -> bytes:
    for r in capture:
        if r.get("dir") == direction and r.get("type") == msg_type and "frame_hex" in r:
            return bytes.fromhex(r["frame_hex"])
    raise RuntimeError(f"missing frame dir={direction} type={msg_type:#x}")

def main():
    ap = argparse.ArgumentParser(description="Replay ctunnel handshake frames against a server.")
    ap.add_argument("--server-host", default="127.0.0.1")
    ap.add_argument("--server-port", type=int, required=True)
    ap.add_argument("--capture", required=True, help="JSON produced by mitm_proxy_record.py")
    args = ap.parse_args()

    cap = load_capture(args.capture)

    client_hello = pick_first(cap, "c2s", 0x01)
    client_finish = pick_first(cap, "c2s", 0x03)

    print("[replay] connecting to server...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((args.server_host, args.server_port))
    print("[replay] connected")

    print("[replay] sending replayed ClientHello...")
    send_frame(s, client_hello)

    print("[replay] reading fresh ServerHello from server (and discarding)...")
    sh = read_frame(s)
    # Optional: print first bytes
    ln = struct.unpack(">I", sh[:4])[0]
    stype = sh[4] if ln > 0 else None
    print(f"[replay] got frame len={ln} type={stype:#x}")

    print("[replay] sending replayed ClientFinish (should FAIL)...")
    send_frame(s, client_finish)

    # Try to see if server keeps connection alive (it shouldn't establish)
    try:
        s.settimeout(1.0)
        nxt = s.recv(1)
        if nxt:
            print("[replay] server sent data after replay (unexpected):", nxt.hex())
        else:
            print("[replay] server closed connection (expected)")
    except socket.timeout:
        print("[replay] timeout waiting for server response (often expected)")
    except Exception as e:
        print("[replay] exception after replay (expected):", e)

    s.close()
    print("[replay] done")

if __name__ == "__main__":
    main()