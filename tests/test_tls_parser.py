# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Tests for ClientHello reading / reassembly (:mod:`whydpi.net.tls_parser`)."""

from __future__ import annotations

import socket
import struct
import threading

from whydpi.net.tls_parser import (
    build_minimal_client_hello,
    looks_like_client_hello,
    parse_client_hello,
    read_client_hello,
)


def _split_into_records(hello: bytes, at: int) -> bytes:
    """Re-frame a single-record hello as two TLS records split at handshake `at`."""
    assert hello[0] == 0x16
    version = hello[1:3]
    handshake = hello[5:]
    first, second = handshake[:at], handshake[at:]
    rec1 = b"\x16" + version + struct.pack("!H", len(first)) + first
    rec2 = b"\x16" + version + struct.pack("!H", len(second)) + second
    return rec1 + rec2


def _read_from_bytes(payload: bytes) -> bytes:
    a, b = socket.socketpair()
    try:
        a.sendall(payload)
        a.shutdown(socket.SHUT_WR)
        return read_client_hello(b, timeout_s=2.0)
    finally:
        a.close()
        b.close()


def test_single_record_hello_unchanged() -> None:
    hello = build_minimal_client_hello("goonbox.cr")
    out = _read_from_bytes(hello)
    assert out == hello
    assert parse_client_hello(out).sni == "goonbox.cr"


def test_multi_record_hello_is_reassembled() -> None:
    hello = build_minimal_client_hello("goonbox.cr")
    # Split the handshake near the front so the SNI lands in the *second*
    # record — the worst case for a single-record reader.
    fragmented = _split_into_records(hello, at=6)
    assert fragmented != hello

    out = _read_from_bytes(fragmented)

    # Reassembled into one coherent record carrying the full handshake.
    assert looks_like_client_hello(out)
    assert out[0] == 0x16
    rec_len = struct.unpack_from("!H", out, 3)[0]
    assert rec_len == len(out) - 5
    # SNI is recoverable again and offsets are record-relative.
    view = parse_client_hello(out)
    assert view.sni == "goonbox.cr"
    assert view.sni_offset is not None


def test_non_handshake_passthrough() -> None:
    blob = b"\x17\x03\x03\x00\x05hello"
    out = _read_from_bytes(blob)
    assert out == blob
