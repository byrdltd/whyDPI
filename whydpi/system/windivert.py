# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""WinDivert-backed TLS ClientHello fragmenter (Windows).

Design
======
On Linux we splice every TLS connection through a userspace transparent
proxy (``TransparentTLSProxy``), which gives us the freedom to try multiple
strategies per SNI within a single discovery step.  Windows has no
``iptables REDIRECT`` equivalent that preserves the original destination
cheaply, so we work at the packet layer instead:

* A single :class:`PacketShaper` opens a WinDivert handle that sees every
  ip+tcp packet to/from TCP port 443.
* Outbound packets whose payload starts with a TLS handshake record
  (``0x16 0x03 ...``) and contain a ClientHello are fragmented according
  to the chosen strategy: one incoming packet is replaced by two (or more)
  outgoing packets carrying the same bytes, with monotonically advancing
  TCP sequence numbers.  All other packets are re-injected unchanged.
* Inbound packets from TCP port 443 are inspected to learn whether a
  strategy actually worked: the first payload byte of the server reply
  either starts with a TLS handshake (``0x16``) — success — or is an
  injected block page / RST — failure.  Results feed the same
  :class:`StrategyCache` the Linux engine uses.

Strategy compatibility
----------------------
``record:*`` strategies reframe a single TLS record into two, growing the
byte stream by 5 bytes (a second 5-byte record header).  That breaks TCP
sequence accounting at the packet layer.  On Windows we therefore remap
``record:<x>`` to ``tcp:<x>`` transparently — the DPI-defeating part
(splitting the SNI across segments) is preserved; only the extra TLS
framing is dropped.  The user-visible strategy label still reports the
requested variant for familiarity.

Privileges
----------
``pydivert`` transparently loads the bundled WinDivert driver.  The
service process must run as an Administrator; enforcement lives in the
installer / service wrapper, not here.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Iterable

from ..core.cache import StrategyCache
from ..core.strategy import Strategy, build_plan
from ..net.tls_parser import looks_like_client_hello, parse_client_hello

logger = logging.getLogger(__name__)


# How long we remember an outbound ClientHello before giving up on the
# inbound reply that would tell us whether the strategy worked.  Real TLS
# handshakes always return the first record within a few seconds; anything
# longer is noise.
_STATE_TTL_S = 8.0


@dataclass
class _ConnKey:
    """Canonicalised 4-tuple keyed as (client, server)."""
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int

    def __hash__(self) -> int:  # noqa: D401
        return hash((self.client_ip, self.client_port, self.server_ip, self.server_port))


@dataclass
class _ConnState:
    sni: str
    strategy_label: str
    created_at: float


def _remap_for_packet_layer(strategy: Strategy) -> Strategy:
    """Return a packet-layer-safe variant of *strategy*.

    ``record:*`` strategies cannot run at the packet layer because
    reframing the TLS record adds 5 bytes and desynchronises TCP.  We
    convert them into their ``tcp:*`` counterparts so the SNI still gets
    split across two TCP segments — which is the only part a stateless
    DPI box actually cares about.
    """
    if strategy.layer == "record":
        return Strategy(
            layer="tcp",
            offset_kind=strategy.offset_kind,
            offset_value=strategy.offset_value,
            delay_ms=strategy.delay_ms,
        )
    return strategy


class PacketShaper:
    """Intercepts outbound TLS ClientHellos and re-injects them as
    fragmented TCP segments; observes inbound replies to grow the cache.
    """

    # Match every ip+tcp packet with port 443 in either direction.  We
    # filter further in software because WinDivert's language does not
    # express "payload starts with 0x16".
    _FILTER = "ip and tcp and (tcp.DstPort == 443 or tcp.SrcPort == 443)"

    def __init__(
        self,
        *,
        default_strategy: Strategy,
        fallbacks: Iterable[Strategy],
        cache: StrategyCache,
    ) -> None:
        self._default = _remap_for_packet_layer(default_strategy)
        self._fallbacks = tuple(_remap_for_packet_layer(s) for s in fallbacks)
        self._cache = cache

        self._handle = None  # type: ignore[var-annotated]
        self._thread: threading.Thread | None = None
        self._running = False

        self._pending: dict[_ConnKey, _ConnState] = {}
        self._pending_lock = threading.Lock()

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> None:
        import sys

        if sys.platform != "win32":
            raise RuntimeError(
                "PacketShaper is Windows-only; on Linux use TransparentTLSProxy."
            )

        import pydivert  # deferred: only required on Windows

        self._handle = pydivert.WinDivert(self._FILTER)
        self._handle.open()
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, name="whydpi-shaper", daemon=True
        )
        self._thread.start()
        logger.info(
            "packet shaper active (default=%s, fallbacks=%s)",
            self._default.label(),
            ",".join(s.label() for s in self._fallbacks) or "-",
        )

    def stop(self) -> None:
        self._running = False
        handle = self._handle
        self._handle = None
        if handle is not None:
            try:
                handle.close()
            except Exception as exc:  # noqa: BLE001
                logger.debug("shaper close: %s", exc)
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        logger.info("packet shaper stopped")

    # ------------------------------------------------------------------ main loop

    def _loop(self) -> None:
        handle = self._handle
        if handle is None:
            return
        while self._running:
            try:
                packet = handle.recv()
            except Exception as exc:  # noqa: BLE001
                if self._running:
                    logger.debug("recv failed: %s", exc)
                break
            try:
                if not getattr(packet, "tcp", None):
                    handle.send(packet)
                    continue
                if packet.is_outbound and packet.tcp.dst_port == 443:
                    self._process_outbound(packet)
                elif packet.is_inbound and packet.tcp.src_port == 443:
                    self._process_inbound(packet)
                    handle.send(packet)
                else:
                    handle.send(packet)
            except Exception as exc:  # noqa: BLE001
                logger.debug("dispatch failed: %s", exc)
                try:
                    handle.send(packet)
                except Exception:  # noqa: BLE001
                    pass

    # ------------------------------------------------------------------ outbound

    def _process_outbound(self, packet) -> None:
        payload = bytes(packet.payload or b"")
        handle = self._handle
        if handle is None:
            return

        if not payload or not looks_like_client_hello(payload):
            handle.send(packet)
            return

        view = parse_client_hello(payload)
        sni = (view.sni or "").lower()
        strategy = self._select_strategy(sni)
        plan = build_plan(payload, view, strategy)

        # A plan that yields a single fragment is a no-op at the packet
        # layer; don't pay the cost of rebuilding the packet.
        if len(plan.fragments) < 2:
            handle.send(packet)
            self._track(packet, sni, strategy.label())
            return

        # Sanity: total size must match or we risk desyncing TCP seq.
        total = sum(len(f) for f in plan.fragments)
        if total != len(payload):
            logger.debug(
                "strategy %s produced %dB != original %dB; sending unchanged",
                strategy.label(), total, len(payload),
            )
            handle.send(packet)
            return

        try:
            self._inject_fragments(packet, plan.fragments)
        except Exception as exc:  # noqa: BLE001
            logger.debug("inject failed (%s); passthrough", exc)
            handle.send(packet)
            return

        self._track(packet, sni, strategy.label())

    def _inject_fragments(self, original, fragments: tuple[bytes, ...]) -> None:
        """Re-inject *fragments* as ``len(fragments)`` distinct packets.

        The first fragment reuses the original TCP sequence number; each
        subsequent fragment advances by the number of bytes already sent.
        ACK number, window and flags are preserved — the PSH flag is
        cleared on all but the last fragment so the receiver re-coalesces
        naturally.
        """
        import pydivert  # noqa: F401 (ensures module is loadable)

        handle = self._handle
        if handle is None:
            return

        base_seq = int(original.tcp.seq_num) & 0xFFFFFFFF
        had_psh = bool(getattr(original.tcp, "psh", False))
        cursor = base_seq

        for idx, frag in enumerate(fragments):
            if not frag:
                continue
            is_last = idx == len(fragments) - 1
            # Clone raw bytes so each packet has its own backing buffer.
            pkt = pydivert.Packet(bytes(original.raw), original.address)
            pkt.payload = frag
            pkt.tcp.seq_num = cursor & 0xFFFFFFFF
            # Keep PSH only on the last segment; some stacks refuse
            # partial pushes when they see PSH too early.
            try:
                pkt.tcp.psh = had_psh and is_last
            except AttributeError:
                pass
            cursor = (cursor + len(frag)) & 0xFFFFFFFF
            handle.send(pkt)

    def _select_strategy(self, sni: str) -> Strategy:
        if sni:
            entry = self._cache.get(sni)
            if entry is not None:
                try:
                    return _remap_for_packet_layer(Strategy.parse(entry.strategy))
                except ValueError:
                    pass
        return self._default

    def _track(self, packet, sni: str, strategy_label: str) -> None:
        if not sni:
            return
        key = _ConnKey(
            client_ip=str(packet.src_addr),
            client_port=int(packet.src_port),
            server_ip=str(packet.dst_addr),
            server_port=int(packet.dst_port),
        )
        now = time.monotonic()
        with self._pending_lock:
            self._pending[key] = _ConnState(
                sni=sni, strategy_label=strategy_label, created_at=now
            )
            self._evict_stale_locked(now)

    def _evict_stale_locked(self, now: float) -> None:
        if len(self._pending) < 256:
            return
        cutoff = now - _STATE_TTL_S
        drop = [k for k, v in self._pending.items() if v.created_at < cutoff]
        for k in drop:
            self._pending.pop(k, None)

    # ------------------------------------------------------------------ inbound

    def _process_inbound(self, packet) -> None:
        key = _ConnKey(
            client_ip=str(packet.dst_addr),
            client_port=int(packet.dst_port),
            server_ip=str(packet.src_addr),
            server_port=int(packet.src_port),
        )
        with self._pending_lock:
            state = self._pending.get(key)

        if state is None:
            return

        rst = bool(getattr(packet.tcp, "rst", False))
        payload = bytes(packet.payload or b"")

        if rst:
            self._cache.record_failure(state.sni, state.strategy_label)
            with self._pending_lock:
                self._pending.pop(key, None)
            logger.debug(
                "strategy failed (RST) sni=%s strategy=%s",
                state.sni, state.strategy_label,
            )
            return

        if len(payload) >= 2 and payload[0] == 0x16 and payload[1] == 0x03:
            self._cache.record_success(state.sni, state.strategy_label)
            with self._pending_lock:
                self._pending.pop(key, None)
            logger.debug(
                "strategy ok sni=%s strategy=%s",
                state.sni, state.strategy_label,
            )
            return

        if payload and payload[0] not in (0x15, 0x16):
            # Plain-HTTP block page or anything else that isn't TLS.
            self._cache.record_failure(state.sni, state.strategy_label)
            with self._pending_lock:
                self._pending.pop(key, None)
            logger.debug(
                "strategy produced non-TLS reply sni=%s strategy=%s head=%s",
                state.sni, state.strategy_label, payload[:4].hex(),
            )
