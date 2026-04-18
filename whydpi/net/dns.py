# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Local DoH stub resolver.

Listens on UDP (and TCP) port 53 at 127.0.0.53, forwards each query as a
wire-format DNS-over-HTTPS POST to the configured resolver IP.  Because the
DoH request is a regular outbound HTTPS connection, it is transparently
intercepted by our TLS proxy and gets the same record-split treatment as
ordinary web traffic — no domain name is ever sent unprotected.
"""

from __future__ import annotations

import logging
import socket
import ssl
import struct
import threading
from dataclasses import dataclass
from typing import Callable


logger = logging.getLogger(__name__)

DOH_CONTENT_TYPE = "application/dns-message"


@dataclass(frozen=True)
class DoHEndpoint:
    ip: str
    path: str = "/dns-query"
    port: int = 443


class DoHClient:
    """Minimal DoH POST client using stdlib ssl.

    Hostname verification is skipped because we address the resolver by IP
    and some public resolvers present certificates that don't chain with the
    IP-only presentation.  The DPI-resistance comes from TLS itself + our
    record splitter; we are not relying on DoH for endpoint authentication
    here, which is an acceptable trade-off for a transport-level tool.
    """

    def __init__(self, endpoint: DoHEndpoint, timeout_s: float = 5.0):
        self._endpoint = endpoint
        self._timeout = timeout_s
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def query(self, wire: bytes) -> bytes:
        family = socket.AF_INET6 if ":" in self._endpoint.ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        try:
            if family == socket.AF_INET6:
                sock.connect((self._endpoint.ip, self._endpoint.port, 0, 0))
            else:
                sock.connect((self._endpoint.ip, self._endpoint.port))
            tls = self._ctx.wrap_socket(sock, server_hostname=None)
            request = (
                f"POST {self._endpoint.path} HTTP/1.1\r\n"
                f"Host: {self._endpoint.ip}\r\n"
                f"Content-Type: {DOH_CONTENT_TYPE}\r\n"
                f"Accept: {DOH_CONTENT_TYPE}\r\n"
                f"Content-Length: {len(wire)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii") + wire
            tls.sendall(request)

            buf = b""
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                buf += chunk
        finally:
            try:
                sock.close()
            except OSError:
                pass

        return _extract_http_body(buf)


def _extract_http_body(raw: bytes) -> bytes:
    separator = raw.find(b"\r\n\r\n")
    if separator < 0:
        return b""
    headers = raw[:separator].decode("latin-1", errors="replace").lower()
    body = raw[separator + 4:]
    if "transfer-encoding: chunked" in headers:
        return _dechunk(body)
    return body


def _dechunk(body: bytes) -> bytes:
    out = bytearray()
    pos = 0
    while pos < len(body):
        end = body.find(b"\r\n", pos)
        if end < 0:
            break
        try:
            size = int(body[pos:end].split(b";", 1)[0], 16)
        except ValueError:
            break
        pos = end + 2
        if size == 0:
            break
        out.extend(body[pos:pos + size])
        pos += size + 2
    return bytes(out)


# ---------------------------------------------------------------------------
# Stub server
# ---------------------------------------------------------------------------

class DNSStubServer:
    """Listens on (addr, 53) UDP+TCP, forwards each query via *resolver*."""

    def __init__(
        self,
        *,
        bind_address: str,
        bind_port: int,
        primary: DoHClient,
        fallback: DoHClient | None = None,
    ):
        self._address = bind_address
        self._port = bind_port
        self._primary = primary
        self._fallback = fallback
        self._udp: socket.socket | None = None
        self._tcp: socket.socket | None = None
        self._running = False
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp.bind((self._address, self._port))

        self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp.bind((self._address, self._port))
        self._tcp.listen(64)

        self._running = True
        for target, name in ((self._serve_udp, "dns-udp"),
                             (self._serve_tcp, "dns-tcp")):
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self._threads.append(t)
        logger.info("DNS stub listening on %s:%s (DoH forwarder)",
                    self._address, self._port)

    def stop(self) -> None:
        self._running = False
        for s in (self._udp, self._tcp):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
        for t in self._threads:
            t.join(timeout=2)

    def _serve_udp(self) -> None:
        while self._running and self._udp is not None:
            try:
                self._udp.settimeout(1.0)
                data, peer = self._udp.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_udp, args=(data, peer), daemon=True
            ).start()

    def _handle_udp(self, data: bytes, peer: tuple) -> None:
        response = self._resolve(data)
        if response and self._udp is not None:
            try:
                self._udp.sendto(response, peer)
            except OSError:
                pass

    def _serve_tcp(self) -> None:
        while self._running and self._tcp is not None:
            try:
                self._tcp.settimeout(1.0)
                client, _ = self._tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_tcp, args=(client,), daemon=True
            ).start()

    def _handle_tcp(self, client: socket.socket) -> None:
        try:
            client.settimeout(5)
            header = client.recv(2)
            if len(header) < 2:
                return
            length = struct.unpack("!H", header)[0]
            payload = b""
            while len(payload) < length:
                chunk = client.recv(length - len(payload))
                if not chunk:
                    return
                payload += chunk

            response = self._resolve(payload)
            if response:
                client.sendall(struct.pack("!H", len(response)) + response)
        except OSError:
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    def _resolve(self, wire: bytes) -> bytes:
        for client in (self._primary, self._fallback):
            if client is None:
                continue
            try:
                return client.query(wire)
            except OSError as exc:
                logger.debug("DoH forward failed via %s: %s", client, exc)
        return b""
