from __future__ import annotations

import argparse
import socket
import threading

BUFFER = 4096


def handle_client(conn: socket.socket, address: tuple[str, int]) -> None:
    with conn:
        while True:
            data = conn.recv(BUFFER)
            if not data:
                return
            response = f"peer={address[0]}:{address[1]} bytes={len(data)} | ".encode() + data
            conn.sendall(response)


def serve(host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(64)
        print(f"listening on {host}:{port}")
        while True:
            conn, address = server.accept()
            threading.Thread(target=handle_client, args=(conn, address), daemon=True).start()


def client(host: str, port: int, message: str) -> str:
    with socket.create_connection((host, port), timeout=3) as conn:
        conn.sendall(message.encode())
        conn.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        while True:
            chunk = conn.recv(BUFFER)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode()


def main() -> None:
    parser = argparse.ArgumentParser(description="Minimal TCP echo lab.")
    sub = parser.add_subparsers(dest="mode", required=True)
    server = sub.add_parser("server")
    server.add_argument("--host", default="0.0.0.0")
    server.add_argument("--port", type=int, default=9090)
    sender = sub.add_parser("client")
    sender.add_argument("--host", default="127.0.0.1")
    sender.add_argument("--port", type=int, default=9090)
    sender.add_argument("message")
    args = parser.parse_args()
    if args.mode == "server":
        serve(args.host, args.port)
    else:
        print(client(args.host, args.port, args.message))


if __name__ == "__main__":
    main()
