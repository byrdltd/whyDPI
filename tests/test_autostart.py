# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Tests for Linux XDG autostart opt-in."""

from __future__ import annotations

from pathlib import Path

from whydpi.ui import autostart as a


def test_linux_enable_writes_kde_friendly_desktop(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(a, "IS_LINUX", True)
    monkeypatch.setattr(a, "IS_WINDOWS", False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(a, "_system_autostart_path", lambda: None)
    monkeypatch.setattr(a, "_find_tray_exec", lambda: "/usr/bin/whydpi-tray")

    assert a.set_enabled(True) is True
    path = tmp_path / "autostart" / "whydpi-tray.desktop"
    text = path.read_text(encoding="utf-8")
    assert "Exec=/usr/bin/whydpi-tray" in text
    assert "Hidden=false" in text
    assert "X-GNOME-Autostart-enabled=true" in text
    assert "X-KDE-autostart-phase=2" in text
    assert "Name[tr]=whyDPI" in text
    assert "Comment[tr]=" in text
    assert a.is_enabled() is True

    assert a.set_enabled(False) is True
    assert not path.exists()
    assert a.is_enabled() is False
