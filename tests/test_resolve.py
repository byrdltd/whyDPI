# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import socket

from whydpi.core.resolve import (
    UpstreamTarget,
    client_target,
    dns_alternate_targets,
)


def test_client_target_from_ip() -> None:
    t = client_target("203.0.113.10", 443)
    assert t == UpstreamTarget(ip="203.0.113.10", port=443, source="client")


def test_dns_alternates_capped_and_deduped(monkeypatch) -> None:
    def fake_getaddrinfo(host, port, **kwargs):
        if host == "example.com":
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.20", port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.30", port)),
            ]
        raise AssertionError(host)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    alts = dns_alternate_targets(
        "example.com",
        client_port=443,
        exclude_ips={"203.0.113.10"},
        ipv6_enabled=False,
        max_alternates=2,
    )
    assert len(alts) == 2
    assert {a.ip for a in alts} == {"203.0.113.20", "203.0.113.30"}


def test_dns_alternates_prefer_fresh_prefix(monkeypatch) -> None:
    """An address on a different network prefix than the blocked one is
    tried before a same-prefix sibling — that is where a range block is
    most likely to be escaped."""
    def fake_getaddrinfo(host, port, **kwargs):
        # System resolver only knows the blocked range's siblings.
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("188.114.96.7", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("188.114.97.7", port)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    alts = dns_alternate_targets(
        "cdn.example",
        client_port=443,
        exclude_ips={"188.114.96.7"},
        ipv6_enabled=False,
        max_alternates=3,
        # A diversified resolver surfaces a clean range the system DNS hid.
        extra_resolver=lambda name, v6: ["104.21.66.57"],
    )
    ips = [a.ip for a in alts]
    assert ips[0] == "104.21.66.57"          # different prefix: tried first
    assert "188.114.97.7" in ips             # blocked sibling still a fallback
    assert "188.114.96.7" not in ips         # excluded primary never reappears


def test_dns_alternates_resolver_failure_is_safe(monkeypatch) -> None:
    def fake_getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.50", port))]

    def boom(name, v6):
        raise RuntimeError("resolver down")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    alts = dns_alternate_targets(
        "example.com",
        client_port=443,
        exclude_ips=set(),
        ipv6_enabled=False,
        max_alternates=2,
        extra_resolver=boom,
    )
    assert [a.ip for a in alts] == ["203.0.113.50"]
