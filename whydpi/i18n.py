# Copyright (c) 2026 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Locale detection and lookup for user-visible copy.

Call :func:`t` with a stable key (``tray.notify.ready.title``).  Catalogs
live in :mod:`whydpi.strings`.  Unknown keys fall back to English, then
to the key itself so a missing translation never crashes the UI.

Override with ``WHYDPI_LANG`` (``de``, ``en``, ``es``, ``fr``, ``ru``, ``tr``).
"""

from __future__ import annotations

import locale
import logging
import os
import sys
from typing import Any

from .strings import CATALOGS, DEFAULT_LANG, SUPPORTED

logger = logging.getLogger(__name__)

_LANG_ENV = "WHYDPI_LANG"
_cached: str | None = None


def reset_cache() -> None:
    """Drop the memoized language (tests)."""
    global _cached
    _cached = None


def _windows_ui_lang() -> str | None:
    if sys.platform != "win32":
        return None
    try:
        import ctypes

        langid = ctypes.windll.kernel32.GetUserDefaultUILanguage()  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return None
    # PRIMARYLANGID — see winnt.h LANG_*
    primary = langid & 0x3FF
    return {
        0x07: "de",
        0x0A: "es",
        0x0C: "fr",
        0x19: "ru",
        0x1F: "tr",
    }.get(primary)


def _posix_lang(environ: dict[str, str]) -> str | None:
    for key in ("LC_ALL", "LC_MESSAGES", "LANG"):
        raw = (environ.get(key) or "").strip()
        if not raw or raw == "C" or raw.startswith("C."):
            continue
        tag = raw.split(".", 1)[0].split("@", 1)[0].replace("-", "_")
        primary = tag.split("_", 1)[0].lower()
        if primary in SUPPORTED:
            return primary
    return None


def detect_lang(environ: dict[str, str] | None = None) -> str:
    explicit = environ is not None
    env = environ if explicit else os.environ
    override = (env.get(_LANG_ENV) or "").strip().lower()
    if override in SUPPORTED:
        return override
    posix = _posix_lang(env)
    if posix:
        return posix
    if explicit:
        return DEFAULT_LANG
    win = _windows_ui_lang()
    if win:
        return win
    try:
        loc = locale.getlocale()[0] or ""
    except (TypeError, ValueError):
        loc = ""
    primary = loc.split("_", 1)[0].lower()
    if primary in SUPPORTED:
        return primary
    return DEFAULT_LANG


def lang() -> str:
    global _cached
    if _cached is None:
        _cached = detect_lang()
    return _cached


def t(key: str, **kwargs: Any) -> str:
    """Return the catalog string for ``key`` in the active language."""
    active = lang()
    table = CATALOGS.get(active) or CATALOGS[DEFAULT_LANG]
    text = table.get(key)
    if text is None:
        text = CATALOGS[DEFAULT_LANG].get(key, key)
        if text == key:
            logger.debug("i18n: missing key %s", key)
    if kwargs:
        try:
            return text.format(**kwargs)
        except (KeyError, IndexError, ValueError):
            logger.debug("i18n: format failed for %s", key, exc_info=True)
            return text
    return text
