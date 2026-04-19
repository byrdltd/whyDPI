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
import sys
import time
from pathlib import Path

logger = logging.getLogger(__name__)

ACCEPTANCE_VERSION = "1"

_DISCLAIMER_URL = "https://github.com/byrdltd/whyDPI/blob/main/DISCLAIMER.md"

# Short English summary — full legal text remains in DISCLAIMER.md on GitHub.
_SUMMARY = """whyDPI is educational and research software.

You choose every destination it touches. You are legally responsible
for your use. This tool must not be used to bypass parental controls,
corporate policies you agreed to, court orders, or to access unlawful
content.

By clicking "I have read and accept", you acknowledge DISCLAIMER.md
in full (see link below). If you do not agree, click Quit."""


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


def run_first_run_dialog() -> bool:
    """Block until the user accepts or declines.  Return True to continue."""
    try:
        import tkinter as tk
        from tkinter import font as tkfont
        from tkinter.scrolledtext import ScrolledText
    except ImportError:
        logger.error(
            "consent: tkinter is required for the first-run dialog. "
            "Install python tk bindings (e.g. tk on Arch) or set "
            "WHYDPI_SKIP_DISCLAIMER=1 only for automation."
        )
        return False

    result: dict[str, bool] = {"ok": False}

    root = tk.Tk()
    root.title("whyDPI — acceptable use")
    root.resizable(True, True)
    root.minsize(420, 320)

    try:
        # Centre on screen
        root.update_idletasks()
        w, h = 520, 420
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        root.geometry(f"{w}x{h}+{x}+{y}")
    except tk.TclError:
        pass

    bold = tkfont.Font(family="sans-serif", size=11, weight="bold")
    tk.Label(
        root,
        text="Read before you continue",
        font=bold,
        pady=6,
    ).pack()

    body = ScrolledText(
        root,
        wrap="word",
        height=14,
        width=62,
        font=("sans-serif", 10),
        relief="flat",
        padx=8,
        pady=4,
    )
    body.pack(fill="both", expand=True, padx=12, pady=4)
    body.insert("1.0", _SUMMARY + "\n\nFull text:\n" + _DISCLAIMER_URL)
    body.configure(state="disabled")

    btn = tk.Frame(root)
    btn.pack(pady=10)

    def _accept() -> None:
        result["ok"] = True
        root.destroy()

    def _quit() -> None:
        result["ok"] = False
        root.destroy()

    def _open_full() -> None:
        import webbrowser

        webbrowser.open(_DISCLAIMER_URL)

    tk.Button(btn, text="Open full disclaimer (browser)", command=_open_full).pack(
        side="left", padx=6,
    )
    tk.Button(btn, text="Quit", command=_quit).pack(side="right", padx=6)
    tk.Button(
        btn,
        text="I have read and accept",
        command=_accept,
        default="active",
    ).pack(side="right", padx=6)

    root.protocol("WM_DELETE_WINDOW", _quit)
    root.mainloop()
    return result["ok"]
