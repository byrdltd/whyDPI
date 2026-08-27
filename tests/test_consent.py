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


def test_zenity_text_info_not_yesno() -> None:
    argv = consent._zenity_text_info_argv("/tmp/disclaimer.txt")
    assert argv[0] == "zenity"
    assert "--text-info" in argv
    assert "--yesno" not in argv
    assert "--question" not in argv
    assert any(a.startswith("--checkbox=") for a in argv)
    assert any(a.startswith("--filename=") for a in argv)


def test_native_dialog_skips_kdialog(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)

    def fake_which(name: str) -> str | None:
        if name == "kdialog":
            return "/usr/bin/kdialog"
        if name == "zenity":
            return None
        return None

    monkeypatch.setattr(consent.shutil, "which", fake_which)

    def boom(*_a, **_k):
        raise AssertionError("kdialog must not be invoked")

    monkeypatch.setattr(consent.subprocess, "run", boom)
    assert consent._run_native_dialog() is None


def test_native_dialog_zenity_accept(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(consent.shutil, "which", lambda n: "/usr/bin/zenity" if n == "zenity" else None)

    class _Done:
        returncode = 0

    seen: list[list[str]] = []

    def fake_run(argv, check=False):  # noqa: ARG001
        seen.append(list(argv))
        return _Done()

    monkeypatch.setattr(consent.subprocess, "run", fake_run)
    assert consent._run_native_dialog() is True
    assert seen and seen[0][0] == "zenity"
    assert "--text-info" in seen[0]


def _tk_available() -> bool:
    try:
        import tkinter as tk

        root = tk.Tk()
        root.withdraw()
        root.destroy()
        return True
    except Exception:  # noqa: BLE001
        return False


@pytest.mark.skipif(not _tk_available(), reason="tkinter display not available")
def test_tk_dialog_actions_packed_bottom_first() -> None:
    result = {"ok": False}
    root = consent._build_tk_dialog(result)
    try:
        root.update_idletasks()
        actions = root._consent_actions
        title = root._consent_title
        info = actions.pack_info()
        assert info["side"] == "bottom"
        min_w, min_h = root.minsize()
        chrome_h = title.winfo_reqheight() + actions.winfo_reqheight()
        assert min_h >= chrome_h
        assert min_w >= 1
    finally:
        root.destroy()
