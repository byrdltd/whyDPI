# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""First-run acceptable-use acknowledgement for the graphical tray.

The tray is often the first touch-point after installation.  A one-time
modal ensures operators see the educational-use boundaries before the
engine can start.  Acceptance is persisted under the user's XDG config
dir (Linux) or ``%LOCALAPPDATA%\\whyDPI`` (Windows).

Headless / automation may set ``WHYDPI_SKIP_DISCLAIMER=1`` — documented
only for CI and packagers, not end users.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from ..i18n import t

logger = logging.getLogger(__name__)

ACCEPTANCE_VERSION = "1"

_DISCLAIMER_URL = "https://github.com/byrdltd/whyDPI/blob/main/DISCLAIMER.md"

# Body text may grow; the action row must not.  Used as the floor for the
# scrollable region once title + actions have taken their natural size.
_MIN_BODY_PX = 96
_DIALOG_W = 560
_DIALOG_H = 420


def _state_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "whyDPI"
    xdg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(xdg) / "whydpi"


def acceptance_path() -> Path:
    return _state_dir() / f".disclaimer_accepted_v{ACCEPTANCE_VERSION}"


def has_accepted() -> bool:
    if os.environ.get("WHYDPI_SKIP_DISCLAIMER", "").strip() in ("1", "true", "yes"):
        logger.warning("consent: WHYDPI_SKIP_DISCLAIMER set — skipping acknowledgement")
        return True
    return acceptance_path().is_file()


def mark_accepted() -> None:
    p = acceptance_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + "\n",
        encoding="utf-8",
    )


def _dialog_body() -> str:
    return t("consent.summary") + "\n\n" + t("consent.full_label") + "\n" + _DISCLAIMER_URL


def _lock_chrome_minsize(root, *chrome, min_body_px: int = _MIN_BODY_PX) -> tuple[int, int]:
    """Forbid the window from shrinking past the widgets that must stay visible.

    Measure title + actions (packed first, from the bottom) then set
    ``minsize`` so the WM cannot hide them.  The body is the only
    widget allowed to take leftover space.
    """
    root.update_idletasks()
    need_w = max(w.winfo_reqwidth() for w in chrome) + 48
    need_h = sum(w.winfo_reqheight() for w in chrome) + min_body_px
    root.minsize(need_w, need_h)
    return need_w, need_h


def _zenity_text_info_argv(path: str) -> list[str]:
    """Scrollable zenity dialog with a required acknowledgement checkbox.

    ``kdialog --yesno`` and ``zenity --question`` size to a short prompt
    and clip the button row on KDE when the body is a multi-paragraph
    disclaimer — do not use them here.
    """
    return [
        "zenity",
        "--text-info",
        "--title", t("consent.title"),
        f"--checkbox={t('consent.checkbox')}",
        f"--ok-label={t('consent.continue')}",
        f"--cancel-label={t('consent.quit')}",
        f"--width={_DIALOG_W}",
        f"--height={_DIALOG_H}",
        f"--filename={path}",
    ]


def _run_native_dialog() -> bool | None:
    """DE-native scrollable acknowledgement, or None to fall through to Tk.

    Returns True/False on a real answer, None when no suitable backend
    is available (including Windows, where Tk is the only path).
    """
    if sys.platform == "win32":
        return None
    if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        return None
    if shutil.which("zenity") is None:
        return None

    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".txt", delete=False, encoding="utf-8"
    )
    try:
        handle.write(_dialog_body())
        handle.close()
        argv = _zenity_text_info_argv(handle.name)
        completed = subprocess.run(argv, check=False)
    except OSError:
        return None
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            pass

    if completed.returncode == 0:
        return True
    if completed.returncode in (1, 5):
        # 1 = Cancel / checkbox not confirmed; zenity uses 5 for timeout.
        return False
    logger.debug(
        "consent: zenity exited %s — falling through to Tk",
        completed.returncode,
    )
    return None


def _build_tk_dialog(result: dict[str, bool]):
    """Construct the Tk dialog; caller runs ``mainloop``.  Split out so
    tests can assert pack order and minsize without blocking on a click.

    The window is built *withdrawn*.  The action row is packed
    ``side=bottom`` first so Tk reserves it before the body claims space.
    ``minsize`` + ``geometry`` are applied, then ``deiconify`` — KDE /
    XWayland often ignore ``geometry()`` on an already-mapped window,
    which is what clipped the buttons when the body was packed first.
    """
    import tkinter as tk
    from tkinter import font as tkfont
    from tkinter.scrolledtext import ScrolledText

    root = tk.Tk()
    root.withdraw()
    root.title(t("consent.title"))
    root.resizable(True, True)

    def _accept() -> None:
        result["ok"] = True
        root.destroy()

    def _quit() -> None:
        result["ok"] = False
        root.destroy()

    def _open_full(_event=None) -> None:
        import webbrowser

        webbrowser.open(_DISCLAIMER_URL)

    # Pack from the bottom first so the WM cannot clip the action row
    # even when it ignores geometry() and hands us a short frame.
    actions = tk.Frame(root)
    actions.pack(side="bottom", fill="x", padx=12, pady=(4, 12))

    link = tk.Label(
        actions,
        text=t("consent.open_full"),
        fg="#1a73e8",
        cursor="hand2",
        font=("sans-serif", 10, "underline"),
        anchor="w",
    )
    link.pack(side="top", anchor="w", pady=(0, 8))
    link.bind("<Button-1>", _open_full)

    btn_row = tk.Frame(actions)
    btn_row.pack(side="top", fill="x")
    tk.Button(
        btn_row,
        text=t("consent.accept"),
        command=_accept,
        default="active",
    ).pack(side="right")
    tk.Button(btn_row, text=t("consent.quit"), command=_quit).pack(
        side="right", padx=(0, 8)
    )

    bold = tkfont.Font(family="sans-serif", size=11, weight="bold")
    title = tk.Label(root, text=t("consent.heading"), font=bold, pady=8)
    title.pack(side="top", fill="x")

    body = ScrolledText(
        root,
        wrap="word",
        height=12,
        width=60,
        font=("sans-serif", 10),
        relief="flat",
        padx=8,
        pady=4,
    )
    body.pack(side="top", fill="both", expand=True, padx=12, pady=4)
    body.insert("1.0", _dialog_body())
    body.configure(state="disabled")

    need_w, need_h = _lock_chrome_minsize(root, title, actions)
    try:
        sw = root.winfo_screenwidth() or _DIALOG_W
        sh = root.winfo_screenheight() or _DIALOG_H
        w = min(max(need_w, _DIALOG_W), sw)
        h = min(max(need_h, _DIALOG_H), sh)
        root.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")
    except tk.TclError:
        pass

    root.deiconify()
    try:
        root.lift()
        root.attributes("-topmost", True)
        root.after(200, lambda: root.attributes("-topmost", False))
    except tk.TclError:
        pass

    root.protocol("WM_DELETE_WINDOW", _quit)
    root.bind("<Return>", lambda _e: _accept())
    root.bind("<Escape>", lambda _e: _quit())
    root._consent_title = title  # type: ignore[attr-defined]
    root._consent_body = body  # type: ignore[attr-defined]
    root._consent_actions = actions  # type: ignore[attr-defined]
    return root


def _run_tk_dialog() -> bool:
    try:
        import tkinter as tk  # noqa: F401
    except ImportError:
        logger.error("consent: tkinter is required for the first-run dialog")
        print(t("consent.error.no_tk"), file=sys.stderr)
        return False

    result: dict[str, bool] = {"ok": False}
    root = _build_tk_dialog(result)
    root.mainloop()
    return result["ok"]


def run_first_run_dialog() -> bool:
    """Block until the user accepts or declines.  Return True to continue."""
    native = _run_native_dialog()
    if native is not None:
        return native
    return _run_tk_dialog()
