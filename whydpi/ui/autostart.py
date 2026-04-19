# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Cross-platform "launch on login" helper for the tray.

The tray menu exposes a single Boolean choice — *Launch whyDPI on
login* — that must behave sensibly on every supported deployment shape:

* **Linux, package install** (AUR / .deb / .rpm) — the packaging rules
  drop a ``whydpi-tray.desktop`` file into ``/etc/xdg/autostart/`` so
  autostart is on by default for everyone.  Opting out therefore means
  writing a per-user override that hides the system-wide entry, which
  XDG specifies via a ``Hidden=true`` key in the same-named file under
  ``$XDG_CONFIG_HOME/autostart/``.
* **Linux, pip install** — no system-wide entry exists.  Opting in
  means writing a fresh ``whydpi-tray.desktop`` with a working ``Exec``
  line under ``$XDG_CONFIG_HOME/autostart/``.  Opting out means
  deleting it.
* **Windows** — the tray executable ships with a
  ``requireAdministrator`` UAC manifest, which means the HKCU ``Run``
  key is *not* a viable autostart path: Windows blocks manifest-
  elevated binaries from auto-launching through the Run keys because
  doing so would pop a UAC prompt on every logon.  The Inno Setup
  installer's optional autostart task uses ``schtasks /SC ONLOGON /RL
  HIGHEST`` for exactly this reason, and so do we: the task runs as
  the user at logon with the "highest available" privileges and
  therefore fires silently without prompting.  Opting in writes a per-
  user scheduled task named ``whyDPI Tray``; opting out deletes it.
  Task Scheduler state is scoped to the user, so uninstalling the
  binary leaves at most an orphaned task that ``schtasks`` will
  happily delete with a clean "element not found" on next toggle.

The module deliberately has zero runtime dependencies on pystray or
Pillow — it is pure stdlib so it can be imported from a headless
context (e.g. ``whydpi --setup-autostart``) without pulling in the
graphical stack.
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")


# XDG paths -------------------------------------------------------------------

_SYSTEM_AUTOSTART_CANDIDATES = (
    Path("/etc/xdg/autostart/whydpi-tray.desktop"),
    Path("/usr/share/xdg/autostart/whydpi-tray.desktop"),
)


def _user_autostart_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "autostart" / "whydpi-tray.desktop"


def _system_autostart_path() -> Path | None:
    for cand in _SYSTEM_AUTOSTART_CANDIDATES:
        if cand.exists():
            return cand
    return None


def _read_desktop_kv(path: Path) -> dict[str, str]:
    """Return the ``[Desktop Entry]`` section as a flat dict.

    This is a permissive parser — we don't validate keys beyond trimming
    whitespace, because the output is only ever fed back into a writer
    that emits a canonical layout.
    """
    data: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return data
    in_entry = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_entry = line.lower() == "[desktop entry]"
            continue
        if not in_entry or "=" not in line:
            continue
        k, v = line.split("=", 1)
        data[k.strip()] = v.strip()
    return data


def _write_desktop(path: Path, kv: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["[Desktop Entry]"]
    # Emit keys in a stable order so round-tripping produces clean diffs.
    ordered = sorted(kv.items(), key=lambda kv2: kv2[0])
    for k, v in ordered:
        lines.append(f"{k}={v}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _find_tray_exec() -> str | None:
    """Best-effort absolute path to the tray entry point for a pip install.

    When the package is installed via ``pip install whydpi[tray]`` the
    console-script wrapper lives on ``PATH`` as ``whydpi-tray``; falling
    back to ``python -m whydpi --tray`` keeps us working in a dev
    checkout where the console script isn't registered yet.
    """
    exe = shutil.which("whydpi-tray")
    if exe:
        return exe
    py = sys.executable or "python3"
    return f"{py} -m whydpi --tray"


# Linux -----------------------------------------------------------------------

def _linux_get() -> bool:
    user = _user_autostart_path()
    if user.exists():
        kv = _read_desktop_kv(user)
        if kv.get("Hidden", "").lower() == "true":
            return False
        if kv.get("X-GNOME-Autostart-enabled", "").lower() == "false":
            return False
        return True
    return _system_autostart_path() is not None


def _linux_set(enabled: bool) -> bool:
    user = _user_autostart_path()
    system = _system_autostart_path()

    if enabled:
        if system is not None:
            # A system-wide file already launches us — remove any
            # per-user "hidden" override so the default kicks in.
            if user.exists():
                try:
                    user.unlink()
                except OSError as exc:
                    logger.warning("autostart: could not remove %s: %s", user, exc)
                    return False
            return True
        # pip install: write a fresh desktop entry.
        exec_line = _find_tray_exec() or "whydpi-tray"
        kv = {
            "Type": "Application",
            "Name": "whyDPI",
            "Comment": "Adaptive DPI bypass — system tray",
            "Exec": exec_line,
            "Icon": "whydpi",
            "Terminal": "false",
            "Categories": "Network;",
            "X-GNOME-Autostart-enabled": "true",
        }
        try:
            _write_desktop(user, kv)
        except OSError as exc:
            logger.warning("autostart: could not write %s: %s", user, exc)
            return False
        return True

    # Disabling.
    if system is not None:
        # System-wide file is there; override it with Hidden=true under
        # the user config so the user's opt-out persists without
        # requiring root.
        kv = {"Type": "Application", "Hidden": "true", "Name": "whyDPI"}
        try:
            _write_desktop(user, kv)
        except OSError as exc:
            logger.warning("autostart: could not write %s: %s", user, exc)
            return False
        return True
    # pip install: just remove our own file.
    if user.exists():
        try:
            user.unlink()
        except OSError as exc:
            logger.warning("autostart: could not remove %s: %s", user, exc)
            return False
    return True


# Windows ---------------------------------------------------------------------

_WIN_TASK_NAME = "whyDPI Tray"


def _find_tray_exe_windows() -> str | None:
    """Locate the installed ``whydpi-tray.exe`` so we register the
    elevated binary rather than a Python interpreter path.

    The Inno Setup installer drops the tray exe under
    ``%ProgramFiles%\\whyDPI\\whydpi-tray.exe``; a fallback to
    ``shutil.which`` catches Scoop installs and PATH overrides.
    """
    candidates: list[str] = []
    for env in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(env)
        if root:
            candidates.append(os.path.join(root, "whyDPI", "whydpi-tray.exe"))
    for p in candidates:
        if os.path.isfile(p):
            return p
    exe = shutil.which("whydpi-tray")
    return exe


def _run_schtasks(args: list[str]) -> tuple[int, str, str]:
    """Invoke ``schtasks.exe`` without flashing a console window.

    We suppress output because a successful create/delete is silent
    anyway; failures are surfaced via ``returncode`` and captured
    stderr.
    """
    import subprocess  # local: only needed on Windows

    CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
    proc = subprocess.run(
        ["schtasks.exe", *args],
        capture_output=True,
        text=True,
        check=False,
        creationflags=CREATE_NO_WINDOW,  # type: ignore[arg-type]
    )
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _win_get() -> bool:
    rc, _, _ = _run_schtasks(["/Query", "/TN", _WIN_TASK_NAME])
    # ``schtasks /Query`` returns 0 when the task exists, 1 when it
    # doesn't (and writes "ERROR: The system cannot find the file
    # specified." to stderr).  We don't need to parse the XML.
    return rc == 0


def _win_set(enabled: bool) -> bool:
    if enabled:
        exe = _find_tray_exe_windows()
        if not exe:
            logger.warning(
                "autostart: could not locate whydpi-tray.exe for scheduled task"
            )
            return False
        # ``/RL HIGHEST`` lets the manifest-elevated exe run without a
        # UAC prompt at logon.  ``/F`` overwrites an existing task so
        # re-toggling after an upgrade picks up the new binary path.
        rc, _, err = _run_schtasks([
            "/Create", "/F",
            "/SC", "ONLOGON",
            "/RL", "HIGHEST",
            "/TN", _WIN_TASK_NAME,
            "/TR", f'"{exe}"',
        ])
        if rc != 0:
            logger.warning("autostart: schtasks create failed (%d): %s", rc, err.strip())
            return False
        return True
    # Disabling: delete the task.  Non-existence is not a failure.
    rc, _, err = _run_schtasks(["/Delete", "/F", "/TN", _WIN_TASK_NAME])
    if rc != 0 and "cannot find" not in err.lower():
        logger.warning("autostart: schtasks delete failed (%d): %s", rc, err.strip())
        return False
    return True


# Menu-entry helper -----------------------------------------------------------
#
# The AUR/.deb/.rpm packages ship a system-wide ``whydpi-tray.desktop``
# under ``/usr/share/applications`` which makes the tray appear in the
# KDE/GNOME/XFCE/LXQt application launcher out of the box.  A pure
# ``pip install whydpi[tray]`` has no such luck — so on Linux we drop a
# twin file under the user's ``~/.local/share/applications`` on first
# run.  No-op when a system file already exists (avoids shadowing the
# packaged copy with a stale ``Exec`` line after a ``pip --user``
# upgrade that moved the entry point).

def _user_menu_entry_path() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "applications" / "whydpi-tray.desktop"


def _system_menu_entry_exists() -> bool:
    for cand in (
        Path("/usr/share/applications/whydpi-tray.desktop"),
        Path("/usr/local/share/applications/whydpi-tray.desktop"),
    ):
        if cand.exists():
            return True
    return False


def ensure_menu_entry() -> bool:
    """Install a user-level app-launcher entry if none is present.

    Returns ``True`` when an entry exists (either already or freshly
    written), ``False`` on platforms where this doesn't apply or when
    the write failed.  Silent on Windows — the Inno Setup installer
    already registers Start-menu shortcuts.
    """
    if not IS_LINUX:
        return False
    if _system_menu_entry_exists():
        return True
    user = _user_menu_entry_path()
    if user.exists():
        return True
    exec_line = _find_tray_exec() or "whydpi-tray"
    kv = {
        "Type": "Application",
        "Name": "whyDPI",
        "GenericName": "DPI Bypass Controller",
        "Comment": "Start, stop and monitor the whyDPI service from the system tray",
        "Exec": exec_line,
        "Icon": "whydpi",
        "Terminal": "false",
        "Categories": "Network;",
        "Keywords": "dpi;tls;bypass;network;proxy;",
        "StartupNotify": "false",
    }
    try:
        _write_desktop(user, kv)
    except OSError as exc:
        logger.debug("autostart: could not write menu entry %s: %s", user, exc)
        return False
    return True


# Public API ------------------------------------------------------------------

def is_enabled() -> bool:
    """Return ``True`` if the tray is configured to start on login."""
    if IS_WINDOWS:
        return _win_get()
    if IS_LINUX:
        return _linux_get()
    return False


def set_enabled(enabled: bool) -> bool:
    """Enable or disable autostart.  Returns ``True`` on success."""
    if IS_WINDOWS:
        return _win_set(enabled)
    if IS_LINUX:
        return _linux_set(enabled)
    return False


def is_supported() -> bool:
    return IS_WINDOWS or IS_LINUX
