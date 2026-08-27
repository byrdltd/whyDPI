# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Minimal TLS ClientHello reader and parser.

Scope is strictly what our strategy layer needs: detect "is this a TLS
handshake", locate the SNI extension (for midpoint splits and SNI-based
cache lookup), and read the full record off a socket regardless of size.
"""

from __future__ import annotations

import logging
import socket
import struct
from dataclasses import dataclass


logger = logging.getLogger(__name__)

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


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def read_client_hello(sock: socket.socket, timeout_s: float = 5.0) -> bytes:
    """Read a complete TLS ClientHello off *sock*, reassembling if needed.

    A ClientHello handshake message may be fragmented across several TLS
    records.  Modern Chrome does exactly this: its hello carries a large
    post-quantum key share (X25519MLKEM768) plus an Encrypted ClientHello
    extension, pushing it past the boundary BoringSSL uses to split the
    handshake into two records.  If we forwarded only the first record the
    origin would wait forever for the rest and never send a ServerHello, so
    discovery would mark every strategy dead and the browser would see
    ``ERR_CONNECTION_CLOSED``.  curl and Firefox emit a smaller, single-record
    hello, which is why they were unaffected.

    We therefore read every handshake record that makes up the ClientHello and
    splice them into one normalised TLS record.  TLS handshake bytes are
    record-boundary agnostic, so the origin computes the same transcript; the
    SNI parser and fragmentation strategies (which assume a single record) then
    operate on a coherent buffer.  Non-handshake or single-record traffic is
    returned byte-for-byte unchanged.
    """
    old_timeout = sock.gettimeout()
    sock.settimeout(timeout_s)
    try:
        header = _recv_exact(sock, 5)
        if len(header) < 5:
            return header

        if header[0] != TLS_HANDSHAKE:
            try:
                return header + sock.recv(16384)
            except OSError:
                return header

        version = header[1:3]
        first_payload = _recv_exact(sock, struct.unpack_from("!H", header, 3)[0])

        # Single-record hello (curl / Firefox / anything small): unchanged.
        if len(first_payload) < 4 or first_payload[0] != TLS_HS_CLIENT_HELLO:
            return header + first_payload

        hs_len = struct.unpack(">I", b"\x00" + first_payload[1:4])[0]
        needed = 4 + hs_len
        handshake = first_payload
        records_read = 1
        while len(handshake) < needed:
            rec_hdr = _recv_exact(sock, 5)
            if len(rec_hdr) < 5 or rec_hdr[0] != TLS_HANDSHAKE:
                handshake += rec_hdr
                break
            rec_payload = _recv_exact(sock, struct.unpack_from("!H", rec_hdr, 3)[0])
            if not rec_payload:
                break
            handshake += rec_payload
            records_read += 1

        if records_read == 1:
            return header + first_payload

        if len(handshake) >= needed:
            handshake = handshake[:needed]
        logger.debug(
            "reassembled ClientHello from %d TLS records (%d handshake bytes)",
            records_read,
            len(handshake),
        )
        return b"\x16" + version + struct.pack("!H", len(handshake)) + handshake
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
