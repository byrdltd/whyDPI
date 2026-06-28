# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import sys

from whydpi.core import discovery as discovery_mod
from whydpi.core.discovery import (
    DiscoveryResult,
    discover_upstream,
    fragmentation_candidates,
    order_candidates,
    platform_fallbacks,
)
from whydpi.core.failure import FailureKind
from whydpi.core.resolve import UpstreamTarget
from whydpi.core.strategy import Strategy, parse_fallback
from whydpi.net.tls_parser import build_minimal_client_hello, parse_client_hello


def test_order_candidates_includes_passthrough() -> None:
    default = Strategy.parse("record:2")
    ordered = order_candidates(None, default, ())
    assert ordered[-1].layer == "passthrough"


def test_platform_fallbacks_drop_decoy_on_linux() -> None:
    fallbacks = parse_fallback(("record:2", "decoy:5", "chunked:40"))
    if sys.platform.startswith("win"):
        assert any(s.layer == "decoy" for s in platform_fallbacks(fallbacks))
    else:
        assert all(s.layer != "decoy" for s in platform_fallbacks(fallbacks))


def test_order_candidates_cached_first() -> None:
    cached = Strategy.parse("passthrough")
    default = Strategy.parse("record:2")
    ordered = order_candidates(cached, default, ())
    assert ordered[0].layer == "passthrough"


def test_fragmentation_candidates_exclude_passthrough() -> None:
    default = Strategy.parse("record:2")
    frag = fragmentation_candidates(None, default, ())
    assert all(s.layer != "passthrough" for s in frag)


# --- upstream-IP rotation on a uniformly blocked address -------------------

def _hello():
    h = build_minimal_client_hello("goonbox.cr")
    return h, parse_client_hello(h)


def _success_result(target: UpstreamTarget) -> DiscoveryResult:
    return DiscoveryResult(
        strategy=Strategy.parse("passthrough"),
        upstream=object(),  # opaque; discover_upstream just forwards it
        server_preview=b"\x16\x03\x03",
        attempts=[("passthrough", "ok")],
        target=target,
        failure_kind=FailureKind.SUCCESS,
    )


def _blocked_result(target: UpstreamTarget, kind: FailureKind) -> DiscoveryResult:
    return DiscoveryResult(
        strategy=None,
        upstream=None,
        server_preview=b"",
        attempts=[("passthrough", "empty")],
        target=target,
        failure_kind=kind,
    )


def test_discover_rotates_to_alternate_ip_on_dpi_block(monkeypatch) -> None:
    primary_ip, alt_ip = "188.114.96.7", "104.21.66.57"
    visited: list[str] = []

    def fake_at_target(target, **_kw):
        visited.append(target.ip)
        if target.ip == primary_ip:
            return _blocked_result(target, FailureKind.DPI_BLOCK)
        return _success_result(target)

    def fake_alts(sni, **kw):
        # The diversified resolver must be threaded through to here.
        assert kw["extra_resolver"] is not None
        return (UpstreamTarget(ip=alt_ip, port=443, source="dns"),)

    monkeypatch.setattr(discovery_mod, "_discover_at_target", fake_at_target)
    monkeypatch.setattr(discovery_mod, "dns_alternate_targets", fake_alts)

    hello, view = _hello()
    res = discover_upstream(
        sni="goonbox.cr", client_dest_ip=primary_ip, client_dest_port=443,
        hello_bytes=hello, hello_view=view, cached=None,
        default=Strategy.parse("record:2"), fallbacks=(), proxy_mark=0,
        timeout_s=1.0, success_min_bytes=6,
        alt_resolver=lambda name, v6: [alt_ip],
    )
    assert res.failure_kind == FailureKind.SUCCESS
    assert res.target is not None and res.target.ip == alt_ip
    assert visited == [primary_ip, alt_ip]


def test_discover_does_not_rotate_on_recv_error(monkeypatch) -> None:
    primary_ip = "203.0.113.9"

    def fake_at_target(target, **_kw):
        return _blocked_result(target, FailureKind.RECV_ERROR)

    def fake_alts(*_a, **_kw):  # must never be consulted
        raise AssertionError("rotation should not happen on RECV_ERROR")

    monkeypatch.setattr(discovery_mod, "_discover_at_target", fake_at_target)
    monkeypatch.setattr(discovery_mod, "dns_alternate_targets", fake_alts)

    hello, view = _hello()
    res = discover_upstream(
        sni="goonbox.cr", client_dest_ip=primary_ip, client_dest_port=443,
        hello_bytes=hello, hello_view=view, cached=None,
        default=Strategy.parse("record:2"), fallbacks=(), proxy_mark=0,
        timeout_s=1.0, success_min_bytes=6,
    )
    assert res.strategy is None
    assert res.failure_kind == FailureKind.RECV_ERROR
