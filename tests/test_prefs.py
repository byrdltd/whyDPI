# Copyright (c) 2026 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Persisted engine-wanted flag."""

from __future__ import annotations

from pathlib import Path

from whydpi.ui import prefs


def test_engine_wanted_roundtrip(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(prefs.sys, "platform", "linux")
    assert prefs.has_engine_intent() is False
    assert prefs.engine_wanted() is False
    prefs.set_engine_wanted(True)
    assert prefs.has_engine_intent() is True
    assert prefs.engine_wanted() is True
    prefs.set_engine_wanted(False)
    assert prefs.engine_wanted() is False
    assert (tmp_path / "whydpi" / "prefs.json").is_file()
