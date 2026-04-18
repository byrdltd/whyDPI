# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Windows DNS adapter control via ``netsh``.

Phase 1 skeleton.  Mirrors the surface of
:mod:`whydpi.system.resolver` (Linux's ``resolv.conf`` manager) so the
cross-platform engine can call ``configure(servers)`` / ``restore()``
without branching.

In Phase 2 this will enumerate active adapters via
``netsh interface ipv4 show interfaces`` (or better, the IPHLPAPI via
ctypes) and issue::

    netsh interface ipv4 set dnsserver "<adapter>" static 127.0.0.1 primary
    netsh interface ipv6 set dnsserver "<adapter>" static ::1       primary

then restore to DHCP on ``restore()``.

The previous settings are persisted to ``%LOCALAPPDATA%\\whyDPI\\dns.backup.json``
so a crash does not leave the user without a working resolver.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class WindowsDnsManager:
    """Manipulates per-adapter DNS on Windows.  Phase 2 target."""

    def is_configured(self, servers: list[str]) -> bool:
        del servers
        return False

    def configure(self, servers: list[str]) -> None:
        del servers
        raise NotImplementedError(
            "netsh-based DNS control lands in Phase 2 of the Windows port."
        )

    def restore(self) -> None:
        raise NotImplementedError(
            "netsh-based DNS control lands in Phase 2 of the Windows port."
        )
