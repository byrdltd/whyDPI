# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Minimal TLS ClientHello reader and parser.

Scope is strictly what our strategy layer needs: detect "is this a TLS
handshake", locate the SNI extension (for midpoint splits and SNI-based
cache lookup), and read the full record off a socket regardless of size.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass


TLS_HANDSHAKE = 0x16
TLS_HS_CLIENT_HELLO = 0x01
EXT_SERVER_NAME = 0x0000


@dataclass(frozen=True)
class ClientHelloView:
    raw: bytes
    sni: str | None
    sni_offset: int | None
    sni_length: int | None

    @property
    def is_valid(self) -> bool:
        return looks_like_client_hello(self.raw)


def looks_like_client_hello(data: bytes) -> bool:
    return (
        len(data) >= 6
        and data[0] == TLS_HANDSHAKE
        and data[1] == 0x03
        and data[5] == TLS_HS_CLIENT_HELLO
    )


def read_client_hello(sock: socket.socket, timeout_s: float = 5.0) -> bytes:
    """Read exactly one full TLS record from *sock*.

    Returns the bytes received even on partial reads so callers can pass
    arbitrary data through unchanged when it is not a TLS handshake.
    """
    old_timeout = sock.gettimeout()
    sock.settimeout(timeout_s)
    try:
        header = b""
        while len(header) < 5:
            chunk = sock.recv(5 - len(header))
            if not chunk:
                return header
            header += chunk

        if header[0] != TLS_HANDSHAKE:
            try:
                return header + sock.recv(16384)
            except OSError:
                return header

        payload_len = struct.unpack_from("!H", header, 3)[0]
        payload = b""
        while len(payload) < payload_len:
            chunk = sock.recv(payload_len - len(payload))
            if not chunk:
                break
            payload += chunk
        return header + payload
    finally:
        try:
            sock.settimeout(old_timeout)
        except OSError:
            pass


def parse_client_hello(data: bytes) -> ClientHelloView:
    if not looks_like_client_hello(data):
        return ClientHelloView(raw=data, sni=None, sni_offset=None, sni_length=None)

    try:
        pos = 5  # record header
        if data[pos] != TLS_HS_CLIENT_HELLO:
            return ClientHelloView(raw=data, sni=None, sni_offset=None, sni_length=None)
        pos += 1 + 3          # handshake type + length
        pos += 2 + 32         # version + random
        pos += 1 + data[pos]  # session id
        pos += 2 + struct.unpack_from("!H", data, pos)[0]  # cipher suites
        pos += 1 + data[pos]  # compression methods

        if pos + 2 > len(data):
            return ClientHelloView(raw=data, sni=None, sni_offset=None, sni_length=None)
        end = pos + 2 + struct.unpack_from("!H", data, pos)[0]
        pos += 2

        while pos + 4 <= min(end, len(data)):
            ext_type = struct.unpack_from("!H", data, pos)[0]
            ext_len = struct.unpack_from("!H", data, pos + 2)[0]
            body = pos + 4
            if ext_type == EXT_SERVER_NAME and body + 5 <= len(data):
                name_type = data[body + 2]
                name_len = struct.unpack_from("!H", data, body + 3)[0]
                if name_type == 0x00 and body + 5 + name_len <= len(data):
                    name_off = body + 5
                    try:
                        name = data[name_off:name_off + name_len].decode("ascii")
                    except UnicodeDecodeError:
                        name = None
                    return ClientHelloView(
                        raw=data,
                        sni=name,
                        sni_offset=name_off,
                        sni_length=name_len,
                    )
            pos = body + ext_len
    except (struct.error, IndexError):
        pass

    return ClientHelloView(raw=data, sni=None, sni_offset=None, sni_length=None)


def build_minimal_client_hello(server_name: str) -> bytes:
    """Synthetic TLS 1.3-compatible ClientHello used by probe / self-tests.

    Includes the extensions that modern servers require
    (``supported_versions``, ``supported_groups``, ``signature_algorithms``
    and ``key_share``) so they respond with a real ServerHello instead of
    an ``unsupported_extension`` / ``handshake_failure`` alert.
    """
    host = server_name.encode("ascii", "ignore")

    def _ext(type_id: int, body: bytes) -> bytes:
        return struct.pack("!HH", type_id, len(body)) + body

    server_name_ext = _ext(
        0x0000,
        struct.pack("!H", len(host) + 3)
        + b"\x00"
        + struct.pack("!H", len(host))
        + host,
    )
    supported_versions_ext = _ext(
        0x002b,
        b"\x04" + b"\x03\x04" + b"\x03\x03",      # list len 4: TLS1.3, TLS1.2
    )
    supported_groups_ext = _ext(
        0x000a,
        b"\x00\x04" + b"\x00\x1d" + b"\x00\x17",  # x25519, secp256r1
    )
    signature_algorithms_ext = _ext(
        0x000d,
        b"\x00\x08"
        + b"\x04\x03"   # ecdsa_secp256r1_sha256
        + b"\x08\x04"   # rsa_pss_rsae_sha256
        + b"\x04\x01"   # rsa_pkcs1_sha256
        + b"\x02\x01",  # rsa_pkcs1_sha1 (legacy)
    )
    x25519_pubkey = b"\x00" * 32
    key_share_ext = _ext(
        0x0033,
        struct.pack("!H", 2 + 2 + 32)
        + b"\x00\x1d"
        + struct.pack("!H", 32)
        + x25519_pubkey,
    )
    ec_point_formats_ext = _ext(0x000b, b"\x01\x00")
    renegotiation_info_ext = _ext(0xff01, b"\x00")

    extensions = (
        server_name_ext
        + supported_versions_ext
        + supported_groups_ext
        + signature_algorithms_ext
        + key_share_ext
        + ec_point_formats_ext
        + renegotiation_info_ext
    )

    cipher_suites = (
        b"\x13\x01"   # TLS_AES_128_GCM_SHA256
        b"\x13\x02"   # TLS_AES_256_GCM_SHA384
        b"\x13\x03"   # TLS_CHACHA20_POLY1305_SHA256
        b"\xc0\x2b"   # ECDHE-ECDSA-AES128-GCM-SHA256
        b"\xc0\x2f"   # ECDHE-RSA-AES128-GCM-SHA256
        b"\xc0\x2c"   # ECDHE-ECDSA-AES256-GCM-SHA384
        b"\xc0\x30"   # ECDHE-RSA-AES256-GCM-SHA384
        b"\x00\x9c"   # RSA-AES128-GCM-SHA256
    )

    session_id = b"\x20" + (b"\x00" * 32)  # 32-byte empty session id

    body = (
        b"\x03\x03"
        + (b"\x00" * 32)
        + session_id
        + struct.pack("!H", len(cipher_suites))
        + cipher_suites
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
