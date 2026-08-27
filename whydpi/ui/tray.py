# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Cross-platform system-tray icon for whyDPI.

On Linux the tray delegates service lifecycle to ``systemd`` via
``pkexec``.  Start (and opting into login autostart) runs
``systemctl enable --now`` so protection survives reboot; Stop runs
``disable --now``.  The tray itself runs unprivileged.

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

from ..i18n import t
from . import prefs as _prefs

logger = logging.getLogger(__name__)

SERVICE = "whydpi.service"
_POLL_SECONDS = 2.0
_START_SETTLE_S = 45.0
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
        cmd = self._priv_launcher() + ["systemctl", "enable", "--now", SERVICE]
        logger.info("tray: launching: %s", " ".join(cmd))
        subprocess.Popen(cmd)

    def stop(self) -> None:
        cmd = self._priv_launcher() + ["systemctl", "disable", "--now", SERVICE]
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


# Windows single-instance enforcement ---------------------------------------
#
# Two tray processes ruin Windows in subtle, user-visible ways:
#
# * Both open WinDivert handles on the same filters (TCP/443, UDP/443,
#   UDP/53).  WinDivert delivers every matching packet to *one* handle
#   at a time in priority order; with equal priorities the choice is
#   effectively non-deterministic.  The QUIC reject path needs the
#   outbound UDP/443 packet *and* the synthetic ICMP reply to traverse
#   the same handle, otherwise the injection races with the second
#   process's drop/passthrough and Chromium/Electron-based desktop
#   apps never see ECONNREFUSED and keep hanging on the
#   "Starting..." splash.
# * Both hijackers send duplicate DoH queries for the same UDP/53
#   question and inject two synthetic replies — the second one arrives
#   after the resolver already cached the first, but on Windows the
#   stray datagram raises "unexpected source" warnings in some
#   resolvers.
# * The onefile PyInstaller bootloader is unhappy when two copies of
#   the exe are alive — overlapping ``pydivert`` DLL handles in
#   ``_MEIxxxx`` temp dirs mean one process's cleanup fails ("Failed
#   to remove temporary directory" popup) on quit.
#
# The first tray that wins ``CreateMutexW(bInitialOwner=TRUE)`` on the
# ``Local\whyDPI-Tray`` namespace runs the full icon + engine; any
# subsequent launch (reboot + autostart ONLOGON task firing again,
# user double-clicking the Start-menu shortcut while the autostart
# tray is already up) sees ``ERROR_ALREADY_EXISTS`` and exits with a
# single user-visible toast.  The mutex lives in the "Local\" namespace
# so different user sessions on the same box (RDP, Fast User Switch)
# each get their own tray without colliding.
_SINGLETON_MUTEX = "Local\\whyDPI-Tray"


def _acquire_singleton_windows():
    """Acquire the per-session singleton mutex.

    Returns ``(handle, already_running)``.  ``handle`` is kept alive
    for the process lifetime (never closed) — the mutex is released
    automatically when the process dies so we don't need an atexit
    hook.  ``already_running`` is ``True`` when another whyDPI tray
    already holds the mutex; the caller should surface a message and
    exit.
    """
    if not IS_WINDOWS:
        return None, False
    try:
        import ctypes  # type: ignore
        from ctypes import wintypes  # type: ignore

        ERROR_ALREADY_EXISTS = 183

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        CreateMutexW = kernel32.CreateMutexW
        CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        CreateMutexW.restype = wintypes.HANDLE
        GetLastError = kernel32.GetLastError
        GetLastError.restype = wintypes.DWORD

        handle = CreateMutexW(None, True, _SINGLETON_MUTEX)
        err = GetLastError()
        if not handle:
            logger.debug("tray: CreateMutex failed (err=%d) — skipping singleton", err)
            return None, False
        if err == ERROR_ALREADY_EXISTS:
            return handle, True
        return handle, False
    except Exception as exc:  # noqa: BLE001
        logger.debug("tray: singleton check skipped: %s", exc)
        return None, False


def _notify_already_running_windows() -> None:
    """Show a single user-visible toast when a second tray is refused.

    Without feedback the user clicks the Start-menu icon, nothing
    appears in their tray (because the existing icon was already
    there), and they conclude whyDPI is broken.  A short MessageBox
    explains what happened and nudges them to the existing icon.
    """
    if not IS_WINDOWS:
        return
    try:
        import ctypes  # type: ignore

        # MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND
        flags = 0x00000000 | 0x00000040 | 0x00010000
        ctypes.windll.user32.MessageBoxW(  # type: ignore[attr-defined]
            None,
            t("tray.notify.already.body"),
            t("tray.notify.already.title"),
            flags,
        )
    except Exception:  # noqa: BLE001
        pass


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
# Set in :func:`run` so Windows toasts can use pystray's notify().
_TRAY_ICON = None


def _notify(summary: str, body: str = "") -> None:
    """Fire a best-effort desktop notification.

    Users repeatedly reported "I can't tell whether whyDPI is actually
    running" — the tooltip and icon tint are there, but easy to miss on
    a busy panel.  A toast at startup and on every state transition
    gives unambiguous feedback without modal dialogs.  Silent no-op if
    libnotify isn't installed (common on headless setups).
    """
    if IS_WINDOWS:
        icon = _TRAY_ICON
        if icon is None:
            return
        try:
            icon.notify(body or summary, title=summary)
        except Exception:  # noqa: BLE001
            logger.debug("tray: windows notify failed", exc_info=True)
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


def _confirm_windows_update(version: str) -> bool:
    """Yes/No prompt that is safe to call from a Win32 menu callback."""
    try:
        import ctypes

        text = t("tray.dialog.update.body", version=version)
        # MB_YESNO | MB_ICONQUESTION | MB_SETFOREGROUND
        rc = ctypes.windll.user32.MessageBoxW(  # type: ignore[attr-defined]
            None, text, t("tray.dialog.update.title"), 0x04 | 0x20 | 0x00010000
        )
        return rc == 6  # IDYES
    except Exception as exc:  # noqa: BLE001
        logger.warning("tray: update confirm failed: %s", exc)
        return False


def _print_missing_deps_and_exit(exc: Exception) -> int:
    print(t("tray.error.missing_deps", error=exc), file=sys.stderr)
    return 2


def _print_windows_not_admin_and_exit() -> int:
    print(t("tray.error.not_admin"), file=sys.stderr)
    return 3


_NOTIFY_KIND = {
    "protecting": ("tray.notify.protecting.title", "tray.notify.protecting.body"),
    "ready": ("tray.notify.ready.title", "tray.notify.ready.body"),
    "stopped": ("tray.notify.stopped.title", "tray.notify.stopped.body"),
}


def _poll_tick(state: dict[str, Any], now: bool, monotonic: float) -> str | None:
    """Decide which toast (if any) a poller tick should fire.

    Returns ``protecting``, ``ready``, ``stopped``, or ``None``.  Startup
    never announces ``stopped``: idle is ``ready`` after the engine has
    settled (or a pending start has timed out).
    """
    was = state["running"]
    if now != was:
        state["running"] = now
        if now:
            state["pending_start"] = False
            state["initial_announced"] = True
            return "protecting"
        return "stopped"

    if state["pending_start"]:
        if monotonic >= float(state["start_deadline"]):
            state["pending_start"] = False
            if not now and not state["initial_announced"]:
                state["initial_announced"] = True
                return "ready"
        return None

    if not state["initial_announced"]:
        state["initial_announced"] = True
        return "protecting" if now else "ready"
    return None


def _kick_start(state: dict[str, Any], controller: Any) -> None:
    state["pending_start"] = True
    state["start_deadline"] = time.monotonic() + _START_SETTLE_S
    controller.start()


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

    # KDE/GNOME on Wayland need StatusNotifier/AppIndicator.  pystray's xorg
    # backend is X11-only and crashes on non-Latin-1 WM titles anyway.
    if IS_LINUX and "PYSTRAY_BACKEND" not in os.environ:
        os.environ["PYSTRAY_BACKEND"] = "appindicator"

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

    # Acquire the per-session singleton mutex *before* any WinDivert
    # handle open, consent dialog, or tray icon spawn.  This is the
    # single biggest user-visible bug fixer on Windows: the installer's
    # autostart schtask + a user-initiated Start-menu launch + the
    # Finish-page shellexec could — in the worst case — leave three
    # elevated whydpi-tray.exe instances racing on the same WinDivert
    # filters, which in turn broke QUIC → TCP fallback for
    # Chromium/Electron desktop clients and triggered the
    # ``_MEIxxxx`` cleanup popup.  Holding the mutex
    # keeps the first-launched tray authoritative; later launches exit
    # cleanly with a single informational dialog.
    _singleton_handle = None
    if IS_WINDOWS:
        _singleton_handle, already = _acquire_singleton_windows()
        if already:
            logger.info("tray: another whyDPI tray is already running — exiting")
            _notify_already_running_windows()
            return 0
        # Keep the handle alive on the tray module to match the lifetime
        # of the process; without a reference Python would GC it and
        # release the mutex, defeating the singleton guarantee.
        globals()["_TRAY_SINGLETON_HANDLE"] = _singleton_handle

    from . import consent as _consent

    if not _consent.has_accepted():
        if not _consent.run_first_run_dialog():
            return 4
        _consent.mark_accepted()

    controller = _make_controller()

    if not controller.is_installed():
        print(t("tray.error.service_missing", service=SERVICE), file=sys.stderr)
        return 1

    state: dict[str, Any] = {
        "running": controller.is_running(),
        "stopped_by_user": False,
        "pending_update": None,
        "pending_start": False,
        "start_deadline": 0.0,
        "initial_announced": False,
    }

    # Resolved once; version never changes inside a tray session and
    # the string is read on every title() call below.
    from .. import __version__ as _tray_version

    def current_icon() -> Any:
        return base if state["running"] else gray

    def title() -> str:
        # Tooltip always carries the version so users can verify which
        # build is live without opening About — helpful for regression
        # triage and when support staff ask "what version are you on".
        key = "tray.title.running" if state["running"] else "tray.title.idle"
        return t(key, version=_tray_version)

    def toggle(_icon, _item) -> None:
        if state["running"]:
            _prefs.set_engine_wanted(False)
            state["pending_start"] = False
            controller.stop()
        else:
            _prefs.set_engine_wanted(True)
            _kick_start(state, controller)

    def quit_app(icon, _item) -> None:
        state["stopped_by_user"] = True
        try:
            controller.teardown()
        except Exception as exc:  # noqa: BLE001
            logger.warning("tray: teardown: %s", exc)
        icon.visible = False
        icon.stop()

    def start_stop_label(_item) -> str:
        return t("tray.menu.stop") if state["running"] else t("tray.menu.start")

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
                if target:
                    _prefs.set_engine_wanted(True)
                    if not state["running"]:
                        _kick_start(state, controller)
                    _notify(
                        t("tray.notify.autostart.on.title"),
                        t("tray.notify.autostart.on.body"),
                    )
                else:
                    _notify(
                        t("tray.notify.autostart.off.title"),
                        t("tray.notify.autostart.off.body"),
                    )
            else:
                _notify(
                    t("tray.notify.autostart.fail.title"),
                    t("tray.notify.autostart.fail.body"),
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("tray: autostart toggle failed: %s", exc)

    def update_label(_item) -> str:
        info = state.get("pending_update")
        if info is not None:
            return t("tray.menu.update.install", version=info.version)
        return t("tray.menu.update.check")

    def on_update(_icon, _item) -> None:
        from . import update as _upd

        pending = state.get("pending_update")
        if pending is None:
            def _manual() -> None:
                try:
                    found = _upd.check_for_update(_tray_version, force=True)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("tray: update check failed: %s", exc)
                    _notify(t("tray.notify.update.checkfail.title"), str(exc))
                    return
                if found is None:
                    _notify(
                        t("tray.notify.update.uptodate.title"),
                        t("tray.notify.update.uptodate.body", version=_tray_version),
                    )
                    return
                state["pending_update"] = found
                try:
                    icon.update_menu()
                except Exception:  # noqa: BLE001
                    pass
                _notify(
                    t("tray.notify.update.available.title", version=found.version),
                    t("tray.notify.update.available.body"),
                )

            threading.Thread(
                target=_manual, name="whydpi-update-manual", daemon=True
            ).start()
            return

        if not _confirm_windows_update(pending.version):
            return

        def _apply() -> None:
            try:
                _notify(
                    t("tray.notify.update.installing.title"),
                    t("tray.notify.update.installing.body", version=pending.version),
                )
                should_quit = _upd.apply_update(pending)
            except Exception as exc:  # noqa: BLE001
                logger.warning("tray: apply update failed: %s", exc)
                _notify(t("tray.notify.update.fail.title"), str(exc))
                return
            if should_quit:
                quit_app(icon, None)

        threading.Thread(
            target=_apply, name="whydpi-update-apply", daemon=True
        ).start()

    menu_items: list[Any] = [
        pystray.MenuItem(start_stop_label, toggle, default=True, checked=running_check),
        pystray.MenuItem(t("tray.menu.status"), _show_status),
        pystray.MenuItem(t("tray.menu.cache"), _open_cache),
    ]
    if _autostart.is_supported():
        menu_items.append(
            pystray.MenuItem(
                t("tray.menu.autostart"),
                toggle_autostart,
                checked=autostart_check,
            )
        )
    if IS_WINDOWS:
        menu_items.append(pystray.MenuItem(update_label, on_update))
    # Version is attached to About rather than a standalone disabled
    # entry because KDE/Plasma's DBus StatusNotifier menu renderer
    # (and some GNOME Shell extensions) drop ``enabled=False`` items
    # from the visible menu, even though the Gtk backend renders them
    # greyed out.  Baking the version into an already-enabled entry
    # guarantees it shows up on every supported backend.
    menu_items.extend([
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(t("tray.menu.about", version=_tray_version), _about),
        pystray.MenuItem(t("tray.menu.disclaimer"), _open_disclaimer),
        pystray.MenuItem(t("tray.menu.quit"), quit_app),
    ])
    menu = pystray.Menu(*menu_items)

    icon = pystray.Icon("whydpi", current_icon(), title(), menu)
    globals()["_TRAY_ICON"] = icon

    def poller() -> None:
        while not state["stopped_by_user"]:
            time.sleep(_POLL_SECONDS)
            try:
                now = controller.is_running()
            except Exception:  # noqa: BLE001
                continue
            was = state["running"]
            kind = _poll_tick(state, now, time.monotonic())
            if kind is not None or now != was:
                try:
                    icon.icon = current_icon()
                    icon.title = title()
                    icon.update_menu()
                except Exception:  # noqa: BLE001
                    pass
            if kind:
                title_key, body_key = _NOTIFY_KIND[kind]
                _notify(t(title_key), t(body_key))

    def setup(_icon) -> None:
        _icon.visible = True
        poll_thread = threading.Thread(
            target=poller, name="whydpi-tray-poll", daemon=True
        )
        poll_thread.start()

        # Windows: the tray hosts the engine, so launching the app means
        # protection.  Linux: honour persisted intent (Start last session,
        # or login autostart).  Do not toast here — start is async
        # (thread / pkexec); the poller announces once state has settled.
        wanted = _prefs.engine_wanted()
        if not _prefs.has_engine_intent() and _autostart.is_enabled():
            wanted = True
            _prefs.set_engine_wanted(True)
        should_start = (IS_WINDOWS or wanted) and not state["running"]
        if should_start:
            try:
                _kick_start(state, controller)
            except Exception as exc:  # noqa: BLE001
                logger.warning("tray: auto-start failed: %s", exc)

        if IS_WINDOWS:
            def _update_checker() -> None:
                try:
                    from . import update as _upd

                    found = _upd.check_for_update(_tray_version)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("tray: update check failed: %s", exc)
                    return
                if found is None:
                    return
                state["pending_update"] = found
                try:
                    icon.update_menu()
                except Exception:  # noqa: BLE001
                    pass
                _notify(
                    t("tray.notify.update.available.title", version=found.version),
                    t("tray.notify.update.available.body"),
                )

            threading.Thread(
                target=_update_checker,
                name="whydpi-update-check",
                daemon=True,
            ).start()

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
