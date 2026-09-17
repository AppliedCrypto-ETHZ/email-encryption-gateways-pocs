#!/usr/bin/env python3
"""HTTP request logger for email client probe requests."""

from __future__ import annotations

import argparse
import base64
import json
import socket
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


TRANSPARENT_GIF = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!"
    b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00"
    b"\x00\x02\x02D\x01\x00;"
)


class RequestLoggingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], log_file: Path) -> None:
        super().__init__(server_address, RequestLoggerHandler)
        self.log_file = log_file
        self.log_lock = threading.Lock()


class RequestLoggerHandler(BaseHTTPRequestHandler):
    server: RequestLoggingHTTPServer

    def do_GET(self) -> None:
        self._handle_request()

    def do_HEAD(self) -> None:
        self._handle_request()

    def do_POST(self) -> None:
        self._handle_request()

    def do_PUT(self) -> None:
        self._handle_request()

    def do_PATCH(self) -> None:
        self._handle_request()

    def do_DELETE(self) -> None:
        self._handle_request()

    def do_OPTIONS(self) -> None:
        self._handle_request()

    def do_TRACE(self) -> None:
        self._handle_request()

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _handle_request(self) -> None:
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        body = self._read_body()
        entry = self._build_log_entry(timestamp, body)

        self._write_file_log(entry)
        self._write_stdout_summary(entry)
        self._send_probe_response()

    def _read_body(self) -> bytes:
        content_length = self.headers.get("Content-Length")
        if not content_length:
            return b""

        try:
            length = int(content_length)
        except ValueError:
            return b""

        if length <= 0:
            return b""

        return self.rfile.read(length)

    def _build_log_entry(self, timestamp: str, body: bytes) -> dict[str, Any]:
        headers = [
            {"name": name, "value": value}
            for name, value in self.headers.raw_items()
        ]
        reconstructed_request = self._reconstruct_request(headers, body)
        remote_host, remote_port = self._split_socket_address(self.client_address)
        local_host, local_port = self._split_socket_address(self.connection.getsockname())
        peer_host, peer_port = self._split_socket_address(self.connection.getpeername())

        return {
            "timestamp": timestamp,
            "connection": {
                "client": {"host": remote_host, "port": remote_port},
                "local": {"host": local_host, "port": local_port},
                "peer": {"host": peer_host, "port": peer_port},
                "socket": {
                    "family": self._socket_family_name(self.connection.family),
                    "type": self._socket_type_name(self.connection.type),
                    "proto": self.connection.proto,
                },
            },
            "request": {
                "method": self.command,
                "target": self.path,
                "version": self.request_version,
                "requestline": self.requestline,
                "raw_requestline_base64": base64.b64encode(self.raw_requestline).decode(
                    "ascii"
                ),
                "headers": headers,
                "body_length": len(body),
                "body_base64": base64.b64encode(body).decode("ascii"),
                "reconstructed_request_base64": base64.b64encode(
                    reconstructed_request
                ).decode("ascii"),
            },
        }

    def _reconstruct_request(
        self, headers: list[dict[str, str]], body: bytes
    ) -> bytes:
        header_bytes = b"".join(
            f"{header['name']}: {header['value']}\r\n".encode(
                "iso-8859-1", "backslashreplace"
            )
            for header in headers
        )
        return self.raw_requestline + header_bytes + b"\r\n" + body

    def _write_file_log(self, entry: dict[str, Any]) -> None:
        with self.server.log_lock:
            with self.server.log_file.open("a", encoding="utf-8") as log:
                json.dump(entry, log, ensure_ascii=False, sort_keys=True)
                log.write("\n")

    def _write_stdout_summary(self, entry: dict[str, Any]) -> None:
        request = entry["request"]
        connection = entry["connection"]
        host = self.headers.get("Host", "-")
        user_agent = self.headers.get("User-Agent", "-")
        target = self._ellipsize(request["target"], 240)

        print(
            f'{entry["timestamp"]} '
            f'{connection["client"]["host"]}:{connection["client"]["port"]} '
            f'{request["method"]} {target} {request["version"]} '
            f'body={request["body_length"]}B host="{host}" ua="{user_agent}"',
            flush=True,
        )

    def _send_probe_response(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(TRANSPARENT_GIF)))
        self.end_headers()

        if self.command != "HEAD":
            self.wfile.write(TRANSPARENT_GIF)

    @staticmethod
    def _split_socket_address(address: Any) -> tuple[str, int | None]:
        if isinstance(address, tuple) and len(address) >= 2:
            return str(address[0]), int(address[1])
        return str(address), None

    @staticmethod
    def _socket_family_name(family: socket.AddressFamily) -> str:
        try:
            return socket.AddressFamily(family).name
        except ValueError:
            return str(family)

    @staticmethod
    def _socket_type_name(sock_type: socket.SocketKind) -> str:
        try:
            return socket.SocketKind(sock_type).name
        except ValueError:
            return str(sock_type)

    @staticmethod
    def _ellipsize(value: str, max_length: int) -> str:
        if len(value) <= max_length:
            return value
        return value[: max_length - 3] + "..."


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Log full HTTP requests from email clients as JSON Lines."
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Interface to bind. Use 0.0.0.0 for a public host. Default: %(default)s",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="TCP port to listen on. Default: %(default)s",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=Path("requests.jsonl"),
        help="Append full request and connection details here. Default: %(default)s",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.log_file.parent.mkdir(parents=True, exist_ok=True)

    server = RequestLoggingHTTPServer((args.host, args.port), args.log_file)
    sys.stderr.write(
        f"Listening on {args.host}:{args.port}; appending request logs to "
        f"{args.log_file}\n"
    )
    sys.stderr.flush()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("Shutting down\n")
        sys.stderr.flush()
    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
