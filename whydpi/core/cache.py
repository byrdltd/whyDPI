# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Disk-persistent per-SNI strategy cache.

Stores what fragmentation strategy worked for each hostname we've seen in the
wild.  The cache is never seeded with hostnames: entries appear only when a
connection to that SNI has succeeded.  Format is a plain JSON map so users can
inspect and prune it.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


@dataclass
class Entry:
    strategy: str
    last_success: float = 0.0
    failures: int = 0
    successes: int = 0


@dataclass
class StrategyCache:
    path: Path
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _dirty: bool = field(default=False, repr=False)
    _entries: dict[str, Entry] = field(default_factory=dict, repr=False)
    _flush_timer: threading.Timer | None = field(default=None, repr=False)
    _flush_interval_s: float = field(default=2.0, repr=False)

    @classmethod
    def load(cls, path: Path) -> "StrategyCache":
        cache = cls(path=path)
        try:
            if path.exists():
                with path.open("r", encoding="utf-8") as fh:
                    raw = json.load(fh)
                for host, data in raw.items():
                    cache._entries[host] = Entry(
                        strategy=data["strategy"],
                        last_success=float(data.get("last_success", 0.0)),
                        failures=int(data.get("failures", 0)),
                        successes=int(data.get("successes", 0)),
                    )
        except (OSError, ValueError, KeyError):
            # Corrupt or missing — start fresh silently.
            cache._entries = {}
        return cache

    # ------------------------------------------------------------------ API

    def get(self, sni: str) -> Entry | None:
        if not sni:
            return None
        with self._lock:
            return self._entries.get(sni.lower())

    def record_success(self, sni: str, strategy_label: str) -> None:
        if not sni:
            return
        key = sni.lower()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or entry.strategy != strategy_label:
                entry = Entry(strategy=strategy_label)
            entry.last_success = time.time()
            entry.successes += 1
            self._entries[key] = entry
            self._dirty = True
        self._schedule_flush()

    def record_failure(self, sni: str, strategy_label: str) -> None:
        if not sni:
            return
        key = sni.lower()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return
            if entry.strategy == strategy_label:
                entry.failures += 1
                if entry.failures >= 3:
                    self._entries.pop(key, None)
                self._dirty = True

    def forget(self, sni: str) -> None:
        if not sni:
            return
        with self._lock:
            if self._entries.pop(sni.lower(), None) is not None:
                self._dirty = True

    def wipe(self) -> None:
        """Remove every trace — memory and disk.  Called on graceful shutdown
        so users don't leave a browsing fingerprint behind.
        """
        with self._lock:
            timer = self._flush_timer
            self._flush_timer = None
            self._entries.clear()
            self._dirty = False
        if timer is not None:
            try:
                timer.cancel()
            except Exception:
                pass
        try:
            if self.path.exists():
                self.path.unlink()
        except OSError:
            pass
        # Remove the parent dir too if it is empty and looks like our own.
        try:
            parent = self.path.parent
            if parent.name == "whydpi" and parent.exists():
                try:
                    parent.rmdir()
                except OSError:
                    pass
        except OSError:
            pass

    def known_hosts(self) -> Iterable[str]:
        with self._lock:
            return tuple(self._entries.keys())

    def flush(self) -> None:
        with self._lock:
            if not self._dirty:
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                host: {
                    "strategy": e.strategy,
                    "last_success": e.last_success,
                    "failures": e.failures,
                    "successes": e.successes,
                }
                for host, e in self._entries.items()
            }
            fd, tmp = tempfile.mkstemp(prefix=".cache-", dir=str(self.path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, indent=2, sort_keys=True)
                os.replace(tmp, self.path)
                self._dirty = False
            except OSError:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    def _schedule_flush(self) -> None:
        """Coalesce bursty writes; flush once every few seconds."""
        with self._lock:
            if self._flush_timer is not None and self._flush_timer.is_alive():
                return
            timer = threading.Timer(self._flush_interval_s, self._deferred_flush)
            timer.daemon = True
            self._flush_timer = timer
        timer.start()

    def _deferred_flush(self) -> None:
        try:
            self.flush()
        finally:
            with self._lock:
                self._flush_timer = None
