# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import socket
import struct

from whydpi.net.dns import (
    DNSStubServer,
    DoHResolver,
    decode_addresses,
    encode_dns_query,
)


def _qname(name: str) -> bytes:
    return b"".join(
        struct.pack("!B", len(label)) + label.encode("ascii")
        for label in name.split(".")
    ) + b"\x00"


def _a_response(name: str, ips: list[str]) -> bytes:
    header = b"\x12\x34" + b"\x81\x80" + struct.pack("!HHHH", 1, len(ips), 0, 0)
    question = _qname(name) + struct.pack("!HH", 1, 1)
    answers = b""
    for ip in ips:
        answers += (
            b"\xc0\x0c"                              # pointer to qname
            + struct.pack("!HHIH", 1, 1, 60, 4)      # A, IN, ttl, rdlen
            + socket.inet_aton(ip)
        )
    return header + question + answers


def test_encode_dns_query_sets_rd_and_labels() -> None:
    wire = encode_dns_query("example.com", 1)
    assert wire[2:4] == b"\x01\x00"                  # RD flag, one question
    assert b"\x07example\x03com\x00" in wire
    assert wire[-4:] == struct.pack("!HH", 1, 1)     # qtype A, qclass IN


def test_decode_addresses_reads_a_records() -> None:
    resp = _a_response("example.com", ["1.2.3.4", "5.6.7.8"])
    assert decode_addresses(resp) == ["1.2.3.4", "5.6.7.8"]


def test_decode_addresses_tolerates_garbage() -> None:
    assert decode_addresses(b"") == []
    assert decode_addresses(b"\x00" * 8) == []


class _FakeClient:
    def __init__(self, ips_by_qtype: dict[int, list[str]]):
        self._ips = ips_by_qtype

    def query(self, wire: bytes) -> bytes:
        qtype = struct.unpack("!H", wire[-4:-2])[0]
        ips = self._ips.get(qtype)
        return _a_response("host.example", ips) if ips else b""

    def close(self) -> None:  # pragma: no cover - parity with DoHClient
        pass


def test_doh_resolver_aggregates_distinct_across_clients() -> None:
    # Two resolvers map the same host to different anycast ranges; one range
    # overlaps.  The resolver must return every distinct address, in order,
    # with no duplicates — that union is what lets discovery escape a block
    # that only drops one of the ranges.
    google = _FakeClient({1: ["188.114.96.7", "188.114.97.7"]})
    cloudflare = _FakeClient({1: ["104.21.66.57", "188.114.96.7"]})
    resolver = DoHResolver([google, cloudflare])

    assert resolver.addresses("host.example", ipv6_enabled=False) == [
        "188.114.96.7",
        "188.114.97.7",
        "104.21.66.57",
    ]


def test_doh_resolver_empty_without_clients() -> None:
    assert DoHResolver([]).addresses("host.example") == []


def _parse_counts(msg: bytes) -> tuple[int, int, int, int, int, int]:
    return struct.unpack_from("!HHHHHH", msg, 0)


def test_stub_neutralises_ech_for_https_query() -> None:
    # An HTTPS (type 65) query must come back as NOERROR/NODATA without ever
    # reaching the DoH client, so no ECHConfig is delivered to the browser.
    upstream = _FakeClient({65: ["1.2.3.4"]})
    stub = DNSStubServer(
        bind_address="127.0.0.53",
        bind_port=53,
        primary=upstream,
        neutralize_ech=True,
    )
    query = encode_dns_query("goonbox.cr", 65, txid=0xABCD)
    resp = stub._resolve(query)

    txid, flags, qd, an, ns, ar = _parse_counts(resp)
    assert txid == 0xABCD
    assert flags & 0x8000  # QR set (a response)
    assert flags & 0x000F == 0  # RCODE NOERROR
    assert (qd, an, ns, ar) == (1, 0, 0, 0)
    # Question is echoed back intact.
    assert b"\x07goonbox\x02cr\x00" in resp


def test_stub_passes_through_a_query_when_neutralising() -> None:
    # Ordinary A queries are untouched and still forwarded upstream.
    upstream = _FakeClient({1: ["1.2.3.4"]})
    stub = DNSStubServer(
        bind_address="127.0.0.53",
        bind_port=53,
        primary=upstream,
        neutralize_ech=True,
    )
    query = encode_dns_query("goonbox.cr", 1)
    resp = stub._resolve(query)
    assert decode_addresses(resp) == ["1.2.3.4"]
