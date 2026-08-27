# Copyright (c) 2026 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Tray poller settle logic and Linux systemd argv."""

from __future__ import annotations

from whydpi.ui import tray


def _state(**overrides):
    base = {
        "running": False,
        "pending_start": False,
        "start_deadline": 0.0,
        "initial_announced": False,
    }
    base.update(overrides)
    return base


def test_poll_startup_idle_is_ready_not_stopped() -> None:
    state = _state(running=False)
    assert tray._poll_tick(state, False, 0.0) == "ready"
    assert state["initial_announced"] is True
    assert tray._poll_tick(state, False, 1.0) is None


def test_poll_startup_already_running_is_protecting() -> None:
    state = _state(running=True)
    assert tray._poll_tick(state, True, 0.0) == "protecting"


def test_poll_pending_start_stays_silent_until_running() -> None:
    state = _state(pending_start=True, start_deadline=100.0)
    assert tray._poll_tick(state, False, 1.0) is None
    assert tray._poll_tick(state, True, 2.0) == "protecting"
    assert state["pending_start"] is False
    assert state["running"] is True


def test_poll_pending_start_timeout_is_ready() -> None:
    state = _state(pending_start=True, start_deadline=10.0)
    assert tray._poll_tick(state, False, 11.0) == "ready"
    assert state["pending_start"] is False


def test_poll_user_stop_is_stopped() -> None:
    state = _state(running=True, initial_announced=True)
    assert tray._poll_tick(state, False, 0.0) == "stopped"


def test_linux_start_enable_now(monkeypatch) -> None:
    seen: list[list[str]] = []

    def fake_popen(cmd, *a, **k):  # noqa: ARG001
        seen.append(list(cmd))
        return None

    monkeypatch.setattr(tray.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        tray._LinuxSystemdController, "_priv_launcher", staticmethod(lambda: ["pkexec"])
    )
    ctl = tray._LinuxSystemdController()
    ctl.start()
    ctl.stop()
    assert seen[0] == ["pkexec", "systemctl", "enable", "--now", tray.SERVICE]
    assert seen[1] == ["pkexec", "systemctl", "disable", "--now", tray.SERVICE]
