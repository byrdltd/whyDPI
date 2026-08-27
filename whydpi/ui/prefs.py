# Copyright (c) 2026 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Persisted tray preferences (engine intent, not package files)."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_FILE = "prefs.json"


def _dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "whyDPI"
    xdg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(xdg) / "whydpi"


def _path() -> Path:
    return _dir() / _FILE


def _load() -> dict[str, Any]:
    path = _path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def _save(data: dict[str, Any]) -> None:
    path = _path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        logger.warning("prefs: could not write %s: %s", path, exc)


def has_engine_intent() -> bool:
    return "engine_wanted" in _load()


def engine_wanted() -> bool:
    return bool(_load().get("engine_wanted", False))


def set_engine_wanted(value: bool) -> None:
    data = _load()
    data["engine_wanted"] = bool(value)
    _save(data)
