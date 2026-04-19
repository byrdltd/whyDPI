# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Cross-platform system-tray icon for whyDPI.

On Linux the tray delegates service lifecycle to ``systemd`` via
``pkexec`` so a single polkit prompt per session covers Start and Stop.
The tray itself runs unprivileged.

On Windows there is no equivalent of ``systemctl`` — the expected
installation shape is a single elevated executable, so the tray *is*
the engine host: Start spins up a worker thread that calls the shared
:func:`whydpi.core.engine.run` end-to-end, and Stop signals it to exit.
Both paths share menu layout, icon handling, cache-folder discovery
and graceful-quit behaviour.
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
from types import SimpleNamespace
from typing import Any

logger = logging.getLogger(__name__)

SERVICE = "whydpi.service"
_POLL_SECONDS = 2.0
_ABOUT_URL = "https://github.com/byrdltd/whyDPI"
_DISCLAIMER_URL = "https://github.com/byrdltd/whyDPI/blob/main/DISCLAIMER.md"

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")


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
# Service controllers — one implementation per platform.  Both expose the
# same tiny surface: is_installed / is_running / start / stop / teardown.
# ---------------------------------------------------------------------------

class _LinuxSystemdController:
    """Drives ``systemctl`` with a polkit-aware escalator for Start/Stop."""

    name = "linux-systemd"

    @staticmethod
    def _systemctl(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["systemctl", *args],
            capture_output=True,
            text=True,
            check=False,
        )

    @staticmethod
    def _priv_launcher() -> list[str]:
        for cand in ("pkexec", "kdesu", "gksu"):
            p = shutil.which(cand)
            if p:
                return [p]
        return ["sudo"]

    def is_installed(self) -> bool:
        r = self._systemctl("list-unit-files", SERVICE, "--no-legend")
        return bool(r.stdout.strip())

    def is_running(self) -> bool:
        return self._systemctl("is-active", SERVICE).stdout.strip() == "active"

    def start(self) -> None:
        cmd = self._priv_launcher() + ["systemctl", "start", SERVICE]
        logger.info("tray: launching: %s", " ".join(cmd))
        subprocess.Popen(cmd)

    def stop(self) -> None:
        cmd = self._priv_launcher() + ["systemctl", "stop", SERVICE]
        logger.info("tray: launching: %s", " ".join(cmd))
        subprocess.Popen(cmd)

    def teardown(self) -> None:
        """Nothing to do: systemd owns the lifecycle."""


class _WindowsInProcessController:
    """Runs the whydpi engine as a background thread inside the tray process.

    The Windows build ships a single elevated executable (PyInstaller
    ``--uac-admin``) so the tray already has every privilege the engine
    needs (WinDivert driver load, ``DnsFlushResolverCache`` API).  Spinning
    the engine up in-process removes the need for a Windows Service and
    keeps all state — including the privacy-wiping cache — co-located
    with the UI.
    """

    name = "windows-in-process"

    def __init__(self) -> None:
        self._state = SimpleNamespace(
            running=False,
            thread=None,
            stop_event=None,
            admin_ok=_is_admin_windows(),
        )
        self._lock = threading.Lock()

    def is_installed(self) -> bool:  # noqa: D401
        return True

    def is_running(self) -> bool:
        thread = self._state.thread
        return bool(thread and thread.is_alive() and self._state.running)

    def start(self) -> None:
        with self._lock:
            if self.is_running():
                return
            if not self._state.admin_ok:
                logger.error(
                    "tray: refusing to start engine — whydpi-tray is not "
                    "running elevated; re-launch with admin rights."
                )
                return
            event = threading.Event()
            self._state.stop_event = event

            def _block_until_stop() -> None:
                event.wait()

            def _worker() -> None:
                try:
                    from ..core import engine as _engine
                    from ..settings import load_settings as _load_settings

                    self._state.running = True
                    _engine.run(
                        _load_settings(),
                        configure_resolver=True,
                        block_until=_block_until_stop,
                    )
                except Exception:  # noqa: BLE001
                    logger.exception("tray: engine worker crashed")
                finally:
                    self._state.running = False

            t = threading.Thread(target=_worker, name="whydpi-engine",
                                 daemon=True)
            self._state.thread = t
            t.start()
            logger.info("tray: engine thread started")

    def stop(self) -> None:
        with self._lock:
            event = self._state.stop_event
            if event is not None:
                event.set()
                logger.info("tray: engine stop requested")

    def teardown(self) -> None:
        self.stop()
        t = self._state.thread
        if t is not None:
            t.join(timeout=5)


def _is_admin_windows() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        import ctypes  # type: ignore
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return False


def _make_controller():
    if IS_WINDOWS:
        return _WindowsInProcessController()
    return _LinuxSystemdController()


# ---------------------------------------------------------------------------
# Tray helpers
# ---------------------------------------------------------------------------

def _cache_dir() -> Path:
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "whyDPI"
    for candidate in (
        Path("/run/whydpi"),
        Path.home() / ".cache" / "whydpi",
    ):
        if candidate.exists():
            return candidate
    return Path.home() / ".cache" / "whydpi"


def _show_status(_icon, _item) -> None:
    """Read-only table of learned per-SNI strategies (from strategies.json).

    pystray invokes menu callbacks on a worker thread; Tk is not thread-safe
    on X11/Wayland, so we spawn a fresh interpreter — Tk's main loop runs
    on that process's main thread.

    On Windows, a PyInstaller-built ``whydpi-tray.exe`` does **not** behave
    like ``python.exe -c ...``: the bootloader ignores ``-c`` and restarts
    the tray entry point, which spawns a **second** tray icon.  Use the
    dedicated ``--show-status`` branch in :func:`run` instead (and
    ``python -m whydpi.ui.tray --show-status …`` for unfrozen installs).
    """
    import subprocess

    from ..settings import cache_path, load_settings

    cache_p = cache_path(load_settings())
    env = os.environ.copy()
    env["WHYDPI_STATUS_CACHE"] = str(cache_p)
    popen_kw: dict = {"env": env}
    if not IS_WINDOWS:
        popen_kw["close_fds"] = True
    try:
        if IS_WINDOWS:
            # Frozen one-file exe: ``-c`` is not honoured — see docstring.
            if getattr(sys, "frozen", False):
                cmd = [sys.executable, "--show-status", str(cache_p)]
            else:
                cmd = [
                    sys.executable,
                    "-m",
                    "whydpi.ui.tray",
                    "--show-status",
                    str(cache_p),
                ]
            subprocess.Popen(cmd, **popen_kw)
        else:
            subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    "import os; from pathlib import Path; "
                    "from whydpi.ui.status_window import show_status_window; "
                    "show_status_window(Path(os.environ['WHYDPI_STATUS_CACHE']))",
                ],
                **popen_kw,
            )
    except OSError as exc:
        logger.warning("tray: could not open status window: %s", exc)


def _open_cache(_icon, _item) -> None:
    path = _cache_dir()
    path.mkdir(parents=True, exist_ok=True)
    if IS_WINDOWS:
        try:
            os.startfile(str(path))  # type: ignore[attr-defined]  # Windows-only
        except Exception as exc:  # noqa: BLE001
            logger.warning("tray: unable to open cache folder: %s", exc)
        return
    opener = shutil.which("xdg-open")
    if opener:
        subprocess.Popen([opener, str(path)])


def _about(_icon, _item) -> None:
    webbrowser.open(_ABOUT_URL)


def _open_disclaimer(_icon, _item) -> None:
    """Open the educational-use disclaimer in the default browser.

    The tray is the earliest point a normal (non-technical) user
    interacts with whyDPI — once the installer finishes, the next
    touch-point is this menu.  We surface the disclaimer as a top-
    level menu item rather than burying it under "About" so that
    acceptable-use boundaries are one click away, not two.
    """
    webbrowser.open(_DISCLAIMER_URL)


def _notify_icon_path() -> str:
    """Resolve an absolute filesystem path to our tray PNG.

    ``notify-send --icon=whydpi`` resolves against the system XDG icon
    theme, which is only populated after the .deb/.rpm/AUR install
    drops hicolor icons into ``/usr/share/icons``.  On a fresh pip
    install, and on every developer's local dev tree, no such theme
    entry exists, so libnotify falls back to the dreaded "?" glyph.
    Using an absolute path sidesteps the theme resolver entirely and
    renders the real logo regardless of how whyDPI was installed.
    """
    try:
        # ``as_file`` writes zipped resources out to a real path when
        # needed — for wheels installed normally (our case on Linux +
        # the Windows PyInstaller bundle) it just returns the existing
        # on-disk location.  We leak the temp handle deliberately: the
        # tray runs for the whole session so the file must stay alive
        # past this function's return.
        # Prefer the high-res notify variant, fall back to the 64px tray
        # panel icon if the wheel is built without it.
        assets = resources.files("whydpi.ui").joinpath("_assets")
        for name in ("notify.png", "tray.png"):
            cand = assets.joinpath(name)
            s = str(cand)
            if os.path.isfile(s):
                return s
        return ""
    except Exception:  # noqa: BLE001
        return ""


# Resolved once at import so the notify path doesn't repeatedly hit
# importlib.resources on every state transition.
_ICON_PATH = _notify_icon_path()


def _notify(summary: str, body: str = "") -> None:
    """Fire a best-effort desktop notification.

    Users repeatedly reported "I can't tell whether whyDPI is actually
    running" — the tooltip and icon tint are there, but easy to miss on
    a busy panel.  A toast at startup and on every state transition
    gives unambiguous feedback without modal dialogs.  Silent no-op if
    libnotify isn't installed (common on headless setups).
    """
    if IS_WINDOWS:
        # pystray's own notify works well against the Win32 shell.
        return
    notify_send = shutil.which("notify-send")
    if not notify_send:
        return
    # Prefer the absolute PNG so we render the logo even when the
    # system icon theme has no whydpi entry yet (dev installs, first
    # login after .deb upgrade before gtk-update-icon-cache runs, ...).
    icon = _ICON_PATH if _ICON_PATH and os.path.isfile(_ICON_PATH) else "whydpi"
    try:
        subprocess.Popen(
            [
                notify_send,
                "--app-name=whyDPI",
                f"--icon={icon}",
                "--expire-time=4000",
                summary,
                body,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:  # noqa: BLE001
        pass


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


def _print_windows_not_admin_and_exit() -> int:
    print(
        "whyDPI Windows tray must run as Administrator so that:\n"
        "  * WinDivert can load its kernel driver,\n"
        "  * the DNS packet hijacker can open a WinDivert handle on UDP/53,\n"
        "  * DnsFlushResolverCache can evict ISP-poisoned cache entries.\n"
        "\n"
        "Right-click the whyDPI shortcut and choose 'Run as administrator'.\n"
        "The installer registers the shortcut with a UAC manifest so a normal\n"
        "double-click prompts for elevation automatically.",
        file=sys.stderr,
    )
    return 3


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run() -> int:
    # Child process for "Show status…" on Windows (see :func:`_show_status`).
    for i in range(1, len(sys.argv) - 1):
        if sys.argv[i] == "--show-status":
            from .status_window import show_status_window

            show_status_window(Path(sys.argv[i + 1]))
            return 0

    try:
        import pystray  # type: ignore
    except Exception as exc:  # noqa: BLE001
        return _print_missing_deps_and_exit(exc)
    try:
        base = _load_base_image()
        gray = _desaturate(base)
    except Exception as exc:  # noqa: BLE001
        return _print_missing_deps_and_exit(exc)

    if IS_WINDOWS and not _is_admin_windows():
        return _print_windows_not_admin_and_exit()

    from . import consent as _consent

    # True only when the user just clicked through the modal this session —
    # used to mirror Windows UX: start the engine immediately after consent
    # (Linux: polkit for ``systemctl start``) instead of leaving the service
    # stopped behind a grey tray icon.
    consent_fresh_accept = False
    if not _consent.has_accepted():
        if not _consent.run_first_run_dialog():
            return 4
        consent_fresh_accept = True
        _consent.mark_accepted()

    controller = _make_controller()

    if not controller.is_installed():
        print(
            f"whyDPI service ({SERVICE}) is not installed.\n"
            "Install the whydpi package (AUR, .deb, .rpm) first, then re-run the tray.",
            file=sys.stderr,
        )
        return 1

    state = {"running": controller.is_running(), "stopped_by_user": False}

    def current_icon() -> Any:
        return base if state["running"] else gray

    def title() -> str:
        return "whyDPI — running" if state["running"] else "whyDPI — stopped"

    def toggle(_icon, _item) -> None:
        if state["running"]:
            controller.stop()
        else:
            controller.start()

    def quit_app(icon, _item) -> None:
        state["stopped_by_user"] = True
        try:
            controller.teardown()
        except Exception as exc:  # noqa: BLE001
            logger.warning("tray: teardown: %s", exc)
        icon.visible = False
        icon.stop()

    def start_stop_label(_item) -> str:
        return "Stop whyDPI" if state["running"] else "Start whyDPI"

    def running_check(_item) -> bool:
        return state["running"]

    # Autostart is deliberately a separate checkbox rather than a
    # sub-menu so a user can toggle "should this launch with my
    # computer" without understanding the difference between an XDG
    # autostart file (Linux) and a Task Scheduler ``ONLOGON`` entry
    # (Windows).  The helper module figures out which backend applies.
    from . import autostart as _autostart

    # ``pip install whydpi[tray]`` leaves no app-launcher entry; the
    # packaged installs (AUR/.deb/.rpm/Inno) all do.  Writing a tiny
    # user-level .desktop on first run means the tray shows up under
    # "Network" in every major Linux launcher without requiring root.
    try:
        _autostart.ensure_menu_entry()
    except Exception as exc:  # noqa: BLE001
        logger.debug("tray: ensure_menu_entry failed: %s", exc)

    def autostart_check(_item) -> bool:
        try:
            return _autostart.is_enabled()
        except Exception:  # noqa: BLE001
            return False

    def toggle_autostart(_icon, _item) -> None:
        try:
            target = not _autostart.is_enabled()
            if _autostart.set_enabled(target):
                _notify(
                    "whyDPI will launch on login" if target
                    else "whyDPI will no longer launch on login",
                    "Change takes effect at your next sign-in.",
                )
            else:
                _notify(
                    "Could not change launch-on-login setting",
                    "See whydpi log for details.",
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("tray: autostart toggle failed: %s", exc)

    menu_items: list[Any] = [
        pystray.MenuItem(start_stop_label, toggle, default=True, checked=running_check),
        pystray.MenuItem("Show status…", _show_status),
        pystray.MenuItem("Open cache folder", _open_cache),
    ]
    if _autostart.is_supported():
        menu_items.append(
            pystray.MenuItem(
                "Launch whyDPI on login",
                toggle_autostart,
                checked=autostart_check,
            )
        )
    menu_items.extend([
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("About whyDPI", _about),
        pystray.MenuItem("Acceptable-use & disclaimer", _open_disclaimer),
        pystray.MenuItem("Quit", quit_app),
    ])
    menu = pystray.Menu(*menu_items)

    icon = pystray.Icon("whydpi", current_icon(), title(), menu)

    def poller() -> None:
        while not state["stopped_by_user"]:
            time.sleep(_POLL_SECONDS)
            try:
                now = controller.is_running()
            except Exception:  # noqa: BLE001
                continue
            if now != state["running"]:
                state["running"] = now
                try:
                    icon.icon = current_icon()
                    icon.title = title()
                    icon.update_menu()
                except Exception:  # noqa: BLE001
                    pass
                if now:
                    _notify("whyDPI is protecting your connection",
                            "Traffic is being handled by the adaptive TLS fragmenter.")
                else:
                    _notify("whyDPI stopped",
                            "DNS has been restored to its original servers.")

    def setup(_icon) -> None:
        _icon.visible = True
        t = threading.Thread(target=poller, name="whydpi-tray-poll", daemon=True)
        t.start()

        # On Windows the tray IS the engine host (single elevated
        # process — see _WindowsInProcessController) so the expected UX
        # is "launch the app → you are protected".  Requiring the user
        # to first open the menu and click Start defeated the point of
        # the installer's Finish-page auto-launch: adapter DNS was
        # never redirected, the shaper was never on the wire, and
        # ISP-hijacked DNS answers reached the browser unchanged.
        # Kick the engine off here so the icon turns coloured as soon
        # as the service finishes starting up; the poller (above) will
        # pick up the transition and fire the "active" toast.
        if IS_WINDOWS and not state["running"]:
            try:
                controller.start()
            except Exception as exc:  # noqa: BLE001
                logger.warning("tray: auto-start failed: %s", exc)

        # Linux: after first-run consent, mirror Windows — bring the systemd
        # unit up immediately (``pkexec systemctl start``) instead of leaving
        # the user on a grey icon until they discover the menu.  Also enable
        # launch-on-login when supported so the checkbox matches expectation.
        if IS_LINUX and consent_fresh_accept:
            try:
                if _autostart.is_supported() and not _autostart.is_enabled():
                    _autostart.set_enabled(True)
            except Exception as exc:  # noqa: BLE001
                logger.debug("tray: first-run autostart enable failed: %s", exc)
            if not state["running"]:
                try:
                    controller.start()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("tray: Linux first-run start failed: %s", exc)
            try:
                state["running"] = controller.is_running()
            except Exception:  # noqa: BLE001
                pass

        # Fire a single "I'm here" toast so the user knows the tray
        # autostarted and the current service state, without having to
        # hunt for a grey-vs-colour icon amongst 20 other indicators.
        if state["running"]:
            _notify("whyDPI is active",
                    "Tray running — your connection is being protected.")
        elif IS_LINUX and consent_fresh_accept:
            _notify(
                "Starting whyDPI…",
                "Approve the password prompt (polkit) if shown. "
                "The shield turns blue when the service is active.",
            )
        else:
            _notify("whyDPI tray started",
                    "Service is currently stopped.  Click the tray icon to start it.")

    if "PYSTRAY_BACKEND" in os.environ:
        logger.info("tray backend override: %s", os.environ["PYSTRAY_BACKEND"])

    logger.info(
        "whyDPI tray starting (controller=%s) — service currently %s",
        controller.name,
        "active" if state["running"] else "inactive",
    )
    icon.run(setup=setup)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
