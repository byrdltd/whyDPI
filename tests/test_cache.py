# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Unit tests for :class:`whydpi.core.cache.StrategyCache`."""

from __future__ import annotations

import tempfile
from pathlib import Path

from whydpi.core.cache import StrategyCache


def test_entries_snapshot_sorted() -> None:
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "s.json"
        c = StrategyCache.load(p)
        c.record_success("z.example", "tcp:sni-mid")
        c.record_success("a.example", "chunked:40")
        c.flush()
        snap = c.entries_snapshot()
        hosts = [h for h, _ in snap]
        assert hosts == ["a.example", "z.example"]


def test_record_failure_prunes_after_three() -> None:
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "s.json"
        c = StrategyCache.load(p)
        c.record_success("x.test", "tcp:sni-mid")
        for _ in range(3):
            c.record_failure("x.test", "tcp:sni-mid")
        c.flush()
        c2 = StrategyCache.load(p)
        assert c2.get("x.test") is None
