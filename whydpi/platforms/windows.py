# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Windows engine — WinDivert packet shaper + netsh DNS control.

Phase 1 stub.  The skeleton lets the package import cleanly on Windows
(so CI on ``windows-latest`` can at least verify byte-level portability)
and documents what Phase 2 will wire together.

The real implementation will:

1. Acquire a :class:`~whydpi.system.windivert.PacketShaper` on the
   filter ``outbound and tcp.DstPort == 443 and not loopback``.
2. Drive it with :class:`~whydpi.core.cache.StrategyCache` and the same
   :class:`~whydpi.core.strategy.Strategy` objects the Linux path uses,
   so per-SNI discovery behaves identically.
3. Optionally bring up :class:`~whydpi.net.dns.DNSStubServer` and point
   the active adapter's DNS at ``127.0.0.1`` via
   :class:`~whydpi.system.dns_windows.WindowsDnsManager`.
4. On ``stop`` / Ctrl-C / tray "Stop": reverse every system mutation,
   then call ``cache.wipe()`` to honour the same privacy guarantee
   enjoyed by the Linux build.
"""

from __future__ import annotations

import logging
from typing import Callable

from ..settings import Settings

logger = logging.getLogger(__name__)


_NOT_YET = (
    "Windows engine is not implemented yet (Phase 2 of the port).\n"
    "Run the Linux build or watch "
    "https://github.com/byrdltd/whyDPI for the next release."
)


def run(settings: Settings, *, configure_resolver: bool,
        block_until: Callable[[], None] | None = None) -> int:
    del settings, configure_resolver, block_until
    logger.error(_NOT_YET)
    raise NotImplementedError(_NOT_YET)


def stop_only(settings: Settings) -> int:
    del settings
    logger.error(_NOT_YET)
    raise NotImplementedError(_NOT_YET)
