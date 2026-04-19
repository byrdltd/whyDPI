# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Tests for disclaimer acceptance paths (no GUI)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from whydpi.ui import consent


def test_acceptance_path_under_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("WHYDPI_SKIP_DISCLAIMER", raising=False)
    p = consent.acceptance_path()
    assert "whydpi" in str(p)
    assert not p.exists()
    assert consent.has_accepted() is False
    consent.mark_accepted()
    assert p.exists()
    assert consent.has_accepted() is True


def test_skip_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("WHYDPI_SKIP_DISCLAIMER", "1")
    assert consent.has_accepted() is True
