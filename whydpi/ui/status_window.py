# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Simple read-only view of the per-SNI strategy cache (``strategies.json``).

Lets operators see which hostnames have learned strategies without opening
the raw JSON in an editor.  Hostnames are those your browser or apps
connected to while whyDPI was running — treat the window as sensitive.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def _format_ts(ts: float) -> str:
    if ts <= 0:
        return "—"
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except (OSError, ValueError, OverflowError):
        return "—"


def show_status_window(cache_file: Path) -> None:
    """Open a modal-ish Tk window listing cached SNI → strategy rows."""
    try:
        import tkinter as tk
        from tkinter import ttk
    except ImportError:
        logger.error("status: tkinter not available — cannot show status window")
        return

    from ..core.cache import StrategyCache
    from ..settings import load_settings, cache_path

    path = cache_file
    if not path.is_absolute():
        path = cache_path(load_settings())

    cache = StrategyCache.load(path)
    rows: list[tuple[str, str, int, int, str]] = []
    for host, ent in cache.entries_snapshot():
        rows.append(
            (
                host,
                ent.strategy,
                ent.successes,
                ent.failures,
                _format_ts(ent.last_success),
            ),
        )

    root = tk.Tk()
    root.title("whyDPI — learned strategies")
    root.geometry("720x420")
    root.minsize(520, 280)

    tk.Label(
        root,
        text=(
            "Per-SNI strategies learned at runtime. "
            "Sensitive — only hostnames your traffic used appear here."
        ),
        wraplength=680,
        justify="left",
        pady=6,
    ).pack(anchor="w", padx=8)

    tk.Label(root, text=f"Cache file: {path}", font=("sans-serif", 9)).pack(
        anchor="w", padx=8, pady=(0, 4),
    )

    frame = ttk.Frame(root)
    frame.pack(fill="both", expand=True, padx=8, pady=4)

    cols = ("host", "strategy", "ok", "fail", "last_ok")
    tree = ttk.Treeview(frame, columns=cols, show="headings", height=14)
    tree.heading("host", text="SNI / host")
    tree.heading("strategy", text="Strategy")
    tree.heading("ok", text="Successes")
    tree.heading("fail", text="Failures")
    tree.heading("last_ok", text="Last success")

    tree.column("host", width=220)
    tree.column("strategy", width=160)
    tree.column("ok", width=70, anchor="e")
    tree.column("fail", width=70, anchor="e")
    tree.column("last_ok", width=160)

    scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scroll.set)
    tree.pack(side="left", fill="both", expand=True)
    scroll.pack(side="right", fill="y")

    for r in rows:
        tree.insert("", "end", values=r)
    if not rows:
        tree.insert("", "end", values=("—", "No entries yet", "—", "—", "—"))

    tk.Button(root, text="Close", command=root.destroy).pack(pady=(8, 2))

    # Small read-only version footer so users can confirm which build
    # produced the strategy cache they are looking at without hunting
    # through the log — helpful when diagnosing regressions across
    # packaged releases.
    from .. import __version__ as _version

    tk.Label(
        root,
        text=f"whyDPI v{_version}",
        font=("sans-serif", 8),
        fg="#666666",
    ).pack(pady=(0, 6))

    root.mainloop()
