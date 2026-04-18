# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""System-tray icon for whyDPI.

Phase 3 delivers the real tray for Linux.  It:

* loads a packaged icon from ``whydpi/ui/_assets/tray.png``,
* polls ``systemctl is-active whydpi.service`` every couple of seconds
  and swaps between a colour / desaturated icon depending on state,
* exposes a short menu — *Start / Stop* (via ``pkexec systemctl ...`` so
  polkit handles the single password prompt per session), *Open cache
  folder*, *About*, *Quit*,
* writes nothing, registers no daemon, keeps no state of its own;
  closing the icon or the whole user session has zero side effects on
  the running service.

The same file will drive the Windows tray in Phase 3 once the Windows
engine exposes a `start()`/`stop()` surface equivalent to systemd.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
from importlib import resources
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SERVICE = "whydpi.service"
_POLL_SECONDS = 2.0
_ABOUT_URL = "https://github.com/byrdltd/whyDPI"


# ---------------------------------------------------------------------------
# Image loading — kept in helpers so missing Pillow produces a friendly
# error rather than an import-time crash.
# ---------------------------------------------------------------------------

def _load_base_image():
    from PIL import Image  # type: ignore

    with resources.files("whydpi.ui").joinpath("_assets/tray.png").open("rb") as fp:
        return Image.open(fp).convert("RGBA").copy()


def _desaturate(image):
    from PIL import ImageEnhance  # type: ignore

    # Desaturate and dim slightly so the user can tell at a glance that
    # traffic is currently NOT being intercepted.
    return ImageEnhance.Color(image).enhance(0.0)


# ---------------------------------------------------------------------------
# Service control
# ---------------------------------------------------------------------------

def _systemctl(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["systemctl", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def is_running() -> bool:
    return _systemctl("is-active", SERVICE).stdout.strip() == "active"


def is_installed() -> bool:
    """Whether the systemd unit is present at all."""
    r = _systemctl("list-unit-files", SERVICE, "--no-legend")
    return bool(r.stdout.strip())


def _priv_launcher() -> list[str]:
    """Pick the best polkit-aware launcher available on the host.

    ``pkexec`` is by far the most common; on systems where only ``sudo``
    is installed we fall back to a graphical sudo frontend if present.
    """
    for cand in ("pkexec", "kdesu", "gksu"):
        p = shutil.which(cand)
        if p:
            return [p]
    # Last resort — relies on a TTY but never blocks the tray silently.
    return ["sudo"]


def start_service() -> None:
    cmd = _priv_launcher() + ["systemctl", "start", SERVICE]
    logger.info("tray: launching: %s", " ".join(cmd))
    subprocess.Popen(cmd)


def stop_service() -> None:
    cmd = _priv_launcher() + ["systemctl", "stop", SERVICE]
    logger.info("tray: launching: %s", " ".join(cmd))
    subprocess.Popen(cmd)


# ---------------------------------------------------------------------------
# UI — pystray driver
# ---------------------------------------------------------------------------

def _cache_dir() -> Path:
    for candidate in (
        Path("/run/whydpi"),
        Path.home() / ".cache" / "whydpi",
    ):
        if candidate.exists():
            return candidate
    return Path.home() / ".cache" / "whydpi"


def _open_cache(_icon, _item) -> None:
    path = _cache_dir()
    path.mkdir(parents=True, exist_ok=True)
    opener = shutil.which("xdg-open")
    if opener:
        subprocess.Popen([opener, str(path)])


def _about(_icon, _item) -> None:
    webbrowser.open(_ABOUT_URL)


def _print_missing_deps_and_exit(exc: Exception) -> int:
    print(
        "whyDPI tray requires the optional tray extras:\n"
        "  pip install 'whydpi[tray]'\n"
        "or on Arch Linux:\n"
        "  sudo pacman -S python-pillow python-gobject libayatana-appindicator\n"
        "  pip install --user --break-system-packages pystray\n"
        f"\nunderlying import error: {exc}",
        file=sys.stderr,
    )
    return 2


def run() -> int:
    try:
        import pystray  # type: ignore
    except Exception as exc:  # noqa: BLE001
        return _print_missing_deps_and_exit(exc)
    try:
        base = _load_base_image()
        gray = _desaturate(base)
    except Exception as exc:  # noqa: BLE001
        return _print_missing_deps_and_exit(exc)

    state = {"running": is_running(), "stopped_by_user": False}

    def current_icon() -> Any:
        return base if state["running"] else gray

    def title() -> str:
        return "whyDPI — running" if state["running"] else "whyDPI — stopped"

    def toggle(icon, _item) -> None:
        if state["running"]:
            stop_service()
        else:
            start_service()

    def quit_app(icon, _item) -> None:
        state["stopped_by_user"] = True
        icon.visible = False
        icon.stop()

    def start_stop_label(_item) -> str:
        return "Stop whyDPI" if state["running"] else "Start whyDPI"

    def running_check(_item) -> bool:
        return state["running"]

    menu = pystray.Menu(
        pystray.MenuItem(start_stop_label, toggle, default=True, checked=running_check),
        pystray.MenuItem("Open cache folder", _open_cache),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("About whyDPI", _about),
        pystray.MenuItem("Quit tray", quit_app),
    )

    icon = pystray.Icon("whydpi", current_icon(), title(), menu)

    def poller() -> None:
        while not state["stopped_by_user"]:
            time.sleep(_POLL_SECONDS)
            try:
                now = is_running()
            except Exception:  # noqa: BLE001
                continue
            if now != state["running"]:
                state["running"] = now
                try:
                    icon.icon = current_icon()
                    icon.title = title()
                    # Menu labels / checkmark are driven by callables that
                    # close over ``state``; pystray only re-evaluates them
                    # when the menu is explicitly rebuilt.
                    icon.update_menu()
                except Exception:  # noqa: BLE001
                    pass

    def setup(_icon) -> None:
        _icon.visible = True
        t = threading.Thread(target=poller, name="whydpi-tray-poll", daemon=True)
        t.start()

    if not is_installed():
        print(
            f"whyDPI systemd unit ({SERVICE}) is not installed.\n"
            "Install the whydpi package (AUR, .deb, .rpm) first, then re-run the tray.",
            file=sys.stderr,
        )
        return 1

    # pystray hides the PYSTRAY_BACKEND env var for Linux users; we don't
    # force a choice here.  On KDE Plasma Wayland the appindicator
    # backend maps 1:1 onto StatusNotifierItem so the icon appears
    # without any extension.
    if "PYSTRAY_BACKEND" in os.environ:
        logger.info("tray backend override: %s", os.environ["PYSTRAY_BACKEND"])

    logger.info("whyDPI tray starting — service currently %s",
                "active" if state["running"] else "inactive")
    icon.run(setup=setup)
    return 0
