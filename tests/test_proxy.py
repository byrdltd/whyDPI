# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Passthrough fast-path: peek before committing the client."""

from __future__ import annotations

import tempfile
from pathlib import Path

from whydpi.core.cache import StrategyCache
from whydpi.core.strategy import Strategy
from whydpi.net import proxy as proxy_mod
from whydpi.net.proxy import ProxyContext, _relay_passthrough
from whydpi.net.tls_parser import build_minimal_client_hello, parse_client_hello


def _hello():
    h = build_minimal_client_hello("sni.example")
    return h, parse_client_hello(h)


def _ctx(tmp: str) -> ProxyContext:
    cache = StrategyCache.load(Path(tmp) / "s.json")
    return ProxyContext(
        default_strategy=Strategy.parse("record:2"),
        fallbacks=(),
        proxy_mark=0,
        timeout_s=1.0,
        success_min_bytes=6,
        passthrough_sni=(),
        probe_passthrough_first=True,
        ipv6_enabled=False,
        cache=cache,
    )


def test_relay_passthrough_leaves_client_idle_on_miss(monkeypatch) -> None:
    sent: list[bytes] = []

    class _Client:
        def sendall(self, data):
            sent.append(data)

        def recv(self, _n):
            raise AssertionError("client must not be read on a passthrough miss")

    monkeypatch.setattr(
        proxy_mod,
        "probe_strategy",
        lambda *_a, **_k: (Strategy.parse("passthrough"), None, b"", "empty"),
    )
    hello, view = _hello()
    with tempfile.TemporaryDirectory() as td:
        out = _relay_passthrough(
            _Client(), "203.0.113.1", 443, hello, view, _ctx(td),
            sni="sni.example", cid=1, path="cached-passthrough",
        )
    assert out is None
    assert sent == []


def test_relay_passthrough_splices_preview_on_hit(monkeypatch) -> None:
    preview = b"\x16\x03\x03\x00\x02\x00"
    upstream = object()
    relayed: list[bytes] = []

    def fake_relay(_client, _up, initial_b_to_a=b""):
        relayed.append(initial_b_to_a)
        return 0, len(initial_b_to_a), "ok"

    monkeypatch.setattr(proxy_mod, "_relay", fake_relay)
    monkeypatch.setattr(
        proxy_mod,
        "probe_strategy",
        lambda *_a, **_k: (Strategy.parse("passthrough"), upstream, preview, "ok"),
    )
    hello, view = _hello()
    with tempfile.TemporaryDirectory() as td:
        out = _relay_passthrough(
            object(), "203.0.113.1", 443, hello, view, _ctx(td),
            sni="sni.example", cid=1, path="cached-passthrough",
        )
    assert out is upstream
    assert relayed == [preview]
