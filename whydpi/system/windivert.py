# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""WinDivert-backed TLS packet shaper (Windows).

Phase 1 skeleton.  This module intentionally does *not* import pydivert
at module load time so the package is importable on Linux CI without an
optional dependency fuss; the import happens inside :meth:`PacketShaper.start`.

Phase 2 will put the real logic here.  The contract is:

* ``start()``  - open a ``WinDivert`` handle on
  ``outbound and tcp.DstPort == 443 and not loopback`` and spawn a
  worker thread that loops ``recv -> shape -> send``.
* ``stop()``   - close the handle, join the thread, restore traffic.
* On each outbound TCP payload that starts with ``0x16 0x03`` (TLS
  ClientHello) we parse the SNI via :mod:`whydpi.net.tls_parser`,
  consult the :class:`~whydpi.core.cache.StrategyCache` for a previous
  winner, fall back to the configured default strategy if none, split
  the payload accordingly, and re-inject as two or more packets with
  fresh TCP sequence numbers.
* Inbound responses from the same four-tuple are scanned: a ``0x16``
  handshake record promotes the strategy, a ``RST`` or block page
  demotes it and queues a retry with the next fallback.

No part of this file runs on Linux; the Linux engine ignores it entirely.
"""

from __future__ import annotations

import logging

from ..core.cache import StrategyCache
from ..core.strategy import Strategy

logger = logging.getLogger(__name__)


class PacketShaper:
    """Intercepts and reshapes outbound TLS ClientHello packets.

    Thin stub: the full implementation lands in Phase 2.  Instantiating
    it on a non-Windows host raises immediately so mistakes are loud.
    """

    def __init__(
        self,
        *,
        default_strategy: Strategy,
        fallbacks: list[Strategy],
        cache: StrategyCache,
    ) -> None:
        self.default_strategy = default_strategy
        self.fallbacks = fallbacks
        self.cache = cache
        self._running = False

    def start(self) -> None:
        import sys

        if sys.platform != "win32":
            raise RuntimeError(
                "PacketShaper is Windows-only; on Linux use TransparentTLSProxy."
            )
        raise NotImplementedError(
            "WinDivert shaper lands in Phase 2 of the Windows port."
        )

    def stop(self) -> None:
        self._running = False
