# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Windows DNS adapter control via ``netsh``.

Mirrors the surface of :mod:`whydpi.system.resolver` (the Linux
``resolv.conf`` manager) so the cross-platform engine can call
``configure(servers)`` / ``restore()`` without branching.

Behaviour
=========
On ``configure()`` every "enabled and connected" adapter's DNS is set to
the local stub (typically ``127.0.0.1``).  The prior per-adapter DNS
configuration is captured into
``%LOCALAPPDATA%\\whyDPI\\dns.backup.json`` before any mutation so a crash
does not leave the user without a working resolver — the next clean
shutdown or manual ``whydpi stop`` restores from the backup.

IPv6 is best-effort: if ``netsh interface ipv6`` fails (IPv6 disabled on
the adapter) we proceed with v4 only.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)


_NETSH = "netsh"


@dataclass
class _AdapterState:
    name: str
    ipv4: list[str] = field(default_factory=list)
    ipv4_dhcp: bool = True
    ipv6: list[str] = field(default_factory=list)
    ipv6_dhcp: bool = True


def _default_backup_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / "whyDPI" / "dns.backup.json"


def _run(args: list[str], *, check: bool = False) -> subprocess.CompletedProcess:
    """Invoke ``netsh`` without spawning a visible console window."""
    flags = 0
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # Windows only
    except AttributeError:
        flags = 0
    return subprocess.run(
        args,
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=flags,
    )


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

_IP4_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
_IP6_RE = re.compile(r"([0-9a-fA-F:]{2,})")


def _list_active_adapters() -> list[str]:
    """Return the ``Name`` column of every interface that is both
    Administratively Enabled and Connected."""
    proc = _run([_NETSH, "interface", "show", "interface"])
    if proc.returncode != 0:
        logger.warning("netsh show interface failed: %s", proc.stderr.strip())
        return []
    names: list[str] = []
    for raw in proc.stdout.splitlines():
        line = raw.strip()
        if not line or line.startswith("-") or line.lower().startswith("admin"):
            continue
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        admin, state, _type, name = parts
        if admin.lower() == "enabled" and state.lower() == "connected":
            names.append(name.strip())
    return names


def _parse_dns(output: str) -> tuple[list[str], bool]:
    """Return (servers, is_dhcp) parsed from ``netsh show dnsservers``.

    The tool produces slightly different prose per locale but the two
    signals we need are universal: an IP on the first bullet line, or the
    literal phrase ``DHCP`` / the (translated) word from netsh's own
    help output.  We use a conservative heuristic: if we see *any* IP we
    report the list; otherwise we treat it as DHCP.
    """
    ipv4_servers: list[str] = []
    ipv6_servers: list[str] = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        # netsh yields "  Statically Configured DNS Servers:  192.0.2.1"
        # or simply lines like "  192.0.2.1".  Extract any IPs.
        for m in _IP4_RE.finditer(line):
            ipv4_servers.append(m.group(1))
        # Only try IPv6 if the line isn't already a v4 hit (avoid
        # matching "192.0.2.1" as some weird v6 token).
        if not _IP4_RE.search(line):
            for m in _IP6_RE.finditer(line):
                token = m.group(1)
                if ":" in token and len(token) >= 3:
                    ipv6_servers.append(token)
    servers = ipv4_servers + ipv6_servers
    # A pure DHCP adapter shows no IPs at all.
    return servers, (len(servers) == 0)


def _snapshot_adapter(name: str) -> _AdapterState:
    state = _AdapterState(name=name)

    proc4 = _run([_NETSH, "interface", "ipv4", "show", "dnsservers",
                  f"name={name}"])
    if proc4.returncode == 0:
        servers, dhcp = _parse_dns(proc4.stdout)
        state.ipv4 = [s for s in servers if _IP4_RE.fullmatch(s)]
        state.ipv4_dhcp = dhcp or not state.ipv4

    proc6 = _run([_NETSH, "interface", "ipv6", "show", "dnsservers",
                  f"name={name}"])
    if proc6.returncode == 0:
        servers, dhcp = _parse_dns(proc6.stdout)
        state.ipv6 = [s for s in servers if ":" in s]
        state.ipv6_dhcp = dhcp or not state.ipv6

    return state


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class WindowsDnsManager:
    """Apply / restore per-adapter DNS via ``netsh``."""

    def __init__(self, backup_path: Path | None = None) -> None:
        self._backup_path = backup_path or _default_backup_path()
        self._snapshot: list[_AdapterState] = []

    # ----------------------------------------------------------- introspection

    def is_configured(self, servers: Iterable[str]) -> bool:
        """Return True if every active adapter already points at *servers*
        (order-insensitive, v4 only — v6 is best-effort).
        """
        wanted_v4 = {s for s in servers if _IP4_RE.fullmatch(s)}
        if not wanted_v4:
            return False
        for name in _list_active_adapters():
            state = _snapshot_adapter(name)
            if set(state.ipv4) != wanted_v4:
                return False
        return True

    # ----------------------------------------------------------- mutation

    def configure(self, servers: Iterable[str]) -> None:
        servers = list(servers)
        if not servers:
            raise ValueError("configure(): empty servers list")

        adapters = _list_active_adapters()
        if not adapters:
            logger.warning("no active network adapters found; DNS not changed")
            return

        self._snapshot = [_snapshot_adapter(name) for name in adapters]
        self._save_backup()

        v4_primary = next((s for s in servers if _IP4_RE.fullmatch(s)), None)
        v4_extra = [s for s in servers if _IP4_RE.fullmatch(s) and s != v4_primary]
        v6_primary = next((s for s in servers if ":" in s), None)
        v6_extra = [s for s in servers if ":" in s and s != v6_primary]

        for name in adapters:
            if v4_primary is not None:
                _run([_NETSH, "interface", "ipv4", "set", "dnsservers",
                      f"name={name}", "static", v4_primary, "primary",
                      "validate=no"])
                for idx, extra in enumerate(v4_extra, start=2):
                    _run([_NETSH, "interface", "ipv4", "add", "dnsservers",
                          f"name={name}", extra, f"index={idx}",
                          "validate=no"])
            if v6_primary is not None:
                _run([_NETSH, "interface", "ipv6", "set", "dnsservers",
                      f"name={name}", "static", v6_primary, "primary",
                      "validate=no"])
                for idx, extra in enumerate(v6_extra, start=2):
                    _run([_NETSH, "interface", "ipv6", "add", "dnsservers",
                          f"name={name}", extra, f"index={idx}",
                          "validate=no"])

        logger.info(
            "configured %d adapter(s) to use DNS=%s",
            len(adapters), ",".join(servers),
        )

    def restore(self) -> None:
        if not self._snapshot:
            self._load_backup()
        if not self._snapshot:
            logger.debug("no DNS snapshot to restore")
            return

        for state in self._snapshot:
            if state.ipv4_dhcp:
                _run([_NETSH, "interface", "ipv4", "set", "dnsservers",
                      f"name={state.name}", "dhcp"])
            else:
                # Reset then add in original order.
                _run([_NETSH, "interface", "ipv4", "delete", "dnsservers",
                      f"name={state.name}", "all"])
                for idx, server in enumerate(state.ipv4, start=1):
                    mode = "static" if idx == 1 else "static"
                    if idx == 1:
                        _run([_NETSH, "interface", "ipv4", "set", "dnsservers",
                              f"name={state.name}", mode, server, "primary",
                              "validate=no"])
                    else:
                        _run([_NETSH, "interface", "ipv4", "add", "dnsservers",
                              f"name={state.name}", server, f"index={idx}",
                              "validate=no"])
            if state.ipv6_dhcp:
                _run([_NETSH, "interface", "ipv6", "set", "dnsservers",
                      f"name={state.name}", "dhcp"])
            else:
                _run([_NETSH, "interface", "ipv6", "delete", "dnsservers",
                      f"name={state.name}", "all"])
                for idx, server in enumerate(state.ipv6, start=1):
                    if idx == 1:
                        _run([_NETSH, "interface", "ipv6", "set", "dnsservers",
                              f"name={state.name}", "static", server, "primary",
                              "validate=no"])
                    else:
                        _run([_NETSH, "interface", "ipv6", "add", "dnsservers",
                              f"name={state.name}", server, f"index={idx}",
                              "validate=no"])

        logger.info("restored DNS on %d adapter(s)", len(self._snapshot))
        self._snapshot = []
        self._clear_backup()

    # ----------------------------------------------------------- persistence

    def _save_backup(self) -> None:
        try:
            self._backup_path.parent.mkdir(parents=True, exist_ok=True)
            self._backup_path.write_text(
                json.dumps(
                    [
                        {
                            "name": s.name,
                            "ipv4": s.ipv4,
                            "ipv4_dhcp": s.ipv4_dhcp,
                            "ipv6": s.ipv6,
                            "ipv6_dhcp": s.ipv6_dhcp,
                        }
                        for s in self._snapshot
                    ],
                    indent=2,
                ),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("failed to persist DNS backup: %s", exc)

    def _load_backup(self) -> None:
        try:
            if not self._backup_path.exists():
                return
            raw = json.loads(self._backup_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning("failed to read DNS backup: %s", exc)
            return
        self._snapshot = [
            _AdapterState(
                name=item["name"],
                ipv4=list(item.get("ipv4", [])),
                ipv4_dhcp=bool(item.get("ipv4_dhcp", True)),
                ipv6=list(item.get("ipv6", [])),
                ipv6_dhcp=bool(item.get("ipv6_dhcp", True)),
            )
            for item in raw
        ]

    def _clear_backup(self) -> None:
        try:
            if self._backup_path.exists():
                self._backup_path.unlink()
        except OSError as exc:
            logger.debug("failed to delete DNS backup: %s", exc)
