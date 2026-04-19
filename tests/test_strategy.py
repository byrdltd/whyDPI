# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Unit tests for :class:`whydpi.core.strategy.Strategy`."""

from __future__ import annotations

from whydpi.core.discovery import order_candidates
from whydpi.core.strategy import Strategy


def test_parse_tcp_sni_mid() -> None:
    s = Strategy.parse("tcp:sni-mid")
    assert s.layer == "tcp"
    assert s.offset_kind == "sni-mid"


def test_order_candidates_dedup() -> None:
    a = Strategy.parse("record:sni-mid")
    b = Strategy.parse("tcp:sni-mid")
    c = Strategy.parse("chunked:40")
    ordered = order_candidates(cached=a, default=b, fallbacks=[c, a])
    assert len(ordered) == 3
    assert ordered[0].layer == "record"
