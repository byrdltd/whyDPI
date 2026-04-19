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
byte stream by 5 bytes (a second 5-byte record header).  At the packet
layer this breaks naive TCP sequence accounting — but in practice the
fix is cheap: per-connection we remember the 5-byte "outbound growth"
and, while the connection lives, bump every subsequent client→server
segment's ``seq_num`` by +5 and shrink every server→client ``ack_num``
by -5 on the wire.  Client and server each see a consistent sequence
space; only the injection window carries the extra record header.

This matters because many stateless DPI middleboxes reassemble a
single TLS record split across TCP segments before extracting the
SNI, but fail to reassemble across independent TLS records.  A
shaper that silently downgrades ``record:*`` to ``tcp:*`` therefore
produces zero user-visible bypass on those networks — even though the
userspace proxy used on Linux, where ``record:*`` is applied end-to-end,
succeeds against the same middlebox.  The Windows shaper now applies
``record:*`` truthfully so both platforms deliver identical on-wire
byte patterns.

Privileges
----------
``pydivert`` transparently loads the bundled WinDivert driver.  The
service process must run as an Administrator; enforcement lives in the
installer / service wrapper, not here.
"""

from __future__ import annotations

import ipaddress
import logging
import socket as _socket
import struct as _struct
import threading
import time
from dataclasses import dataclass
from typing import Iterable

from ..core.cache import StrategyCache
from ..core.discovery import discover_parallel, order_candidates
from ..core.strategy import Strategy, build_plan
from ..net.tls_parser import (
    build_minimal_client_hello,
    looks_like_client_hello,
    parse_client_hello,
)
from ._trace import trace, trace_enabled

logger = logging.getLogger(__name__)


# How long we remember an outbound ClientHello before giving up on the
# inbound reply that would tell us whether the strategy worked.  Real TLS
# handshakes always return the first record within a few seconds; anything
# longer is noise.
_STATE_TTL_S = 8.0

# How long we remember an in-flight active-discovery task per SNI, so a
# burst of failing connections from the same SNI only triggers one probe
# (the next connection picks up the cached winner instead of probing
# again).  Shorter than _STATE_TTL_S — by the time a second connection
# arrives the probe is either done or lost.
_DISCOVERY_TTL_S = 20.0

# How long to keep a per-connection TCP seq-rewrite entry if we never
# observe a FIN/RST (the connection ended uncleanly or we missed the
# teardown).  10 s is well beyond any TLS handshake + short request
# round-trip while being short enough that a recycled ephemeral port
# can't realistically collide with a stale entry from a prior
# connection.  Long-lived WebSocket / HTTP/2 streams refresh the entry
# implicitly every time we rewrite a packet on it, so they survive well
# past this window.
_REWRITE_TTL_S = 10.0


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


@dataclass
class _SeqRewrite:
    """Per-connection TCP sequence-number offset.

    ``delta`` is the number of bytes the shaper injected into the C->S
    stream on top of what the client's TCP stack believes it sent.  For
    ``record:*`` splits this is exactly 5 (a second TLS record header);
    for ``tcp:*``/``chunked:*`` splits it is 0.  While ``delta != 0``
    we must rewrite every packet belonging to this 4-tuple:

    * client -> server:  seq_num += delta
    * server -> client:  ack_num -= delta

    State is kept until we see a FIN/RST in either direction or until
    the connection has been idle for ``_REWRITE_TTL_S``.
    """
    delta: int
    created_at: float


def _remap_for_packet_layer(strategy: Strategy) -> Strategy:
    """Historical no-op kept for API compatibility and unit tests.

    Prior versions demoted ``record:*`` to ``tcp:*`` here.  We no longer
    need that because the shaper itself now compensates for the 5-byte
    record-reframing growth with on-the-fly TCP sequence rewriting
    (see :class:`_SeqRewrite`).  Returning the strategy unchanged means
    ``record:2`` on Windows produces the exact same on-wire byte pattern
    it does on Linux.
    """
    return strategy


def _record_delta(strategy: Strategy) -> int:
    """Bytes a strategy adds to the C->S byte stream.

    Only ``record:*`` variants grow the stream — by exactly 5 bytes
    (one extra TLS record header).  Everything else leaves the byte
    count unchanged.
    """
    return 5 if strategy.layer == "record" else 0


class PacketShaper:
    """Intercepts outbound TLS ClientHellos and re-injects them as
    fragmented TCP segments; observes inbound replies to grow the cache.
    """

    # Match every ip+tcp packet with port 443 in either direction, for
    # both IPv4 and IPv6.  We filter further in software because
    # WinDivert's language does not express "payload starts with 0x16".
    _FILTER_TCP = (
        "(ip or ipv6) and tcp and "
        "(tcp.DstPort == 443 or tcp.SrcPort == 443)"
    )
    # Match outbound UDP/443 in both families so we can drop QUIC packets
    # and force browsers to fall back to TCP/443 (which we can fragment).
    _FILTER_QUIC = (
        "(ip or ipv6) and udp and "
        "(udp.DstPort == 443 or udp.SrcPort == 443)"
    )

    def __init__(
        self,
        *,
        default_strategy: Strategy,
        fallbacks: Iterable[Strategy],
        cache: StrategyCache,
        block_quic: bool = True,
        probe_timeout_s: float = 3.0,
        success_min_bytes: int = 6,
    ) -> None:
        self._raw_default = default_strategy
        self._raw_fallbacks = tuple(fallbacks)
        self._default = _remap_for_packet_layer(default_strategy)
        self._fallbacks = tuple(_remap_for_packet_layer(s) for s in self._raw_fallbacks)
        self._cache = cache
        self._block_quic = bool(block_quic)
        self._probe_timeout_s = float(probe_timeout_s)
        self._success_min_bytes = int(success_min_bytes)

        self._handle = None  # type: ignore[var-annotated]
        self._quic_handle = None  # type: ignore[var-annotated]
        self._thread: threading.Thread | None = None
        self._quic_thread: threading.Thread | None = None
        self._running = False

        self._pending: dict[_ConnKey, _ConnState] = {}
        self._pending_lock = threading.Lock()

        # Per-4-tuple TCP sequence-offset state (see class docstring).
        # Keyed by the canonicalised (client, server) pair so both
        # C->S and S->C packets look it up with the same key.
        self._rewrites: dict[_ConnKey, _SeqRewrite] = {}
        self._rewrites_lock = threading.Lock()

        # SNI -> deadline after which a new discovery probe is allowed
        # again.  Prevents a connection storm from spawning N parallel
        # probes to the same host.
        self._discovery_inflight: dict[str, float] = {}
        self._discovery_lock = threading.Lock()

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> None:
        import sys

        if sys.platform != "win32":
            raise RuntimeError(
                "PacketShaper is Windows-only; on Linux use TransparentTLSProxy."
            )

        import pydivert  # deferred: only required on Windows

        self._handle = pydivert.WinDivert(self._FILTER_TCP)
        self._handle.open()
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, name="whydpi-shaper", daemon=True
        )
        self._thread.start()

        if self._block_quic:
            try:
                self._quic_handle = pydivert.WinDivert(self._FILTER_QUIC)
                self._quic_handle.open()
                self._quic_thread = threading.Thread(
                    target=self._quic_loop, name="whydpi-quic-drop", daemon=True,
                )
                self._quic_thread.start()
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "QUIC drop handle failed to open (%s); HTTP/3 may bypass "
                    "the shaper.", exc,
                )
                self._quic_handle = None

        logger.info(
            "packet shaper active (default=%s, fallbacks=%s, quic=%s)",
            self._default.label(),
            ",".join(s.label() for s in self._fallbacks) or "-",
            "blocked" if self._quic_handle is not None else (
                "allowed" if not self._block_quic else "allowed (failed to block)"
            ),
        )
        if trace_enabled():
            logger.info(
                "WHYDPI_TRACE=1: per-packet TCP/443 and UDP/443 events "
                "will be emitted at INFO under whydpi.trace",
            )

    def stop(self) -> None:
        self._running = False
        for attr in ("_quic_handle", "_handle"):
            handle = getattr(self, attr, None)
            setattr(self, attr, None)
            if handle is not None:
                try:
                    handle.close()
                except Exception as exc:  # noqa: BLE001
                    logger.debug("shaper close (%s): %s", attr, exc)
        for tattr in ("_quic_thread", "_thread"):
            t = getattr(self, tattr, None)
            if t is not None:
                t.join(timeout=2)
                setattr(self, tattr, None)
        logger.info("packet shaper stopped")

    # ------------------------------------------------------------------ QUIC reject
    def _quic_loop(self) -> None:
        """Intercept outbound UDP/443 and signal port-unreachable.

        Silently dropping QUIC segments (our prior behaviour) forces
        every QUIC-capable client to wait out its own HTTP/3 timeout
        before retrying over TCP — which, for apps with conservative
        timeouts like the Discord desktop Electron shell, looks like
        a permanent hang on the "Starting..." splash.

        Instead we synthesise and inject an ICMP "Destination
        Unreachable / Port Unreachable" reply aimed back at the
        sending host.  This is the same signal the kernel would emit
        if nothing were listening on UDP/443; sockets translate it
        into ``ECONNREFUSED`` within one RTT, and every major HTTP/3
        stack (Chromium, Firefox, Quinn, picoquic) falls back to
        TCP/443 immediately.

        IPv6 QUIC is rejected with ICMPv6 Type 1 Code 4 using the same
        shape.  If either injection fails we fall back to silent drop
        — the prior behaviour — so the shaper never becomes *less*
        reliable than it was.
        """
        # The pydivert handle was opened and stored on ``self`` by
        # :meth:`start`; we only call ``handle.recv()`` / re-inject, both
        # of which are already-bound methods, so no local import of the
        # module itself is required here.
        handle = self._quic_handle
        if handle is None:
            return
        drops = 0
        rejects = 0
        inject_fail_v4 = 0
        inject_fail_v6 = 0
        first_rejects_logged = 0
        last_log = time.monotonic()
        while self._running:
            try:
                packet = handle.recv()
            except Exception as exc:  # noqa: BLE001
                if self._running:
                    logger.debug("quic recv failed: %s", exc)
                break
            injected = False
            is_v6 = False
            try:
                raw = bytes(getattr(packet, "raw", b"") or b"")
                if raw:
                    is_v6 = ((raw[0] >> 4) & 0x0F) == 6
                # Only synthesize a reject for client-originated
                # UDP/443 (dst=443, outbound).  Server-originated
                # UDP/443 (src=443, inbound) is out-of-band — if any
                # slips through the filter, we just drop it.
                if (
                    getattr(packet, "is_outbound", False)
                    and int(getattr(packet, "dst_port", 0) or 0) == 443
                ):
                    injected = self._inject_icmp_port_unreachable(packet)
                    if not injected:
                        if is_v6:
                            inject_fail_v6 += 1
                        else:
                            inject_fail_v4 += 1
            except Exception as exc:  # noqa: BLE001
                logger.info("quic reject injection crashed: %s", exc)
                injected = False
            if injected:
                rejects += 1
                if first_rejects_logged < 3:
                    try:
                        src = getattr(packet, "src_addr", "?")
                        dst = getattr(packet, "dst_addr", "?")
                        sp = getattr(packet, "src_port", "?")
                        dp = getattr(packet, "dst_port", "?")
                        logger.info(
                            "quic reject injected: v%d %s:%s -> %s:%s (ICMP unreach sent)",
                            6 if is_v6 else 4, src, sp, dst, dp,
                        )
                    except Exception:  # noqa: BLE001
                        pass
                    first_rejects_logged += 1
                if trace_enabled():
                    try:
                        trace(
                            "udp/443 QUIC v%d %s:%s -> %s:%s len=%dB -> ICMP unreach",
                            6 if is_v6 else 4,
                            getattr(packet, "src_addr", "?"),
                            getattr(packet, "src_port", "?"),
                            getattr(packet, "dst_addr", "?"),
                            getattr(packet, "dst_port", "?"),
                            len(raw),
                        )
                    except Exception:  # noqa: BLE001
                        pass
            else:
                drops += 1
                if trace_enabled():
                    try:
                        trace(
                            "udp/443 QUIC v%d %s:%s -> %s:%s len=%dB -> DROP (no ICMP)",
                            6 if is_v6 else 4,
                            getattr(packet, "src_addr", "?"),
                            getattr(packet, "src_port", "?"),
                            getattr(packet, "dst_addr", "?"),
                            getattr(packet, "dst_port", "?"),
                            len(raw),
                        )
                    except Exception:  # noqa: BLE001
                        pass
            now = time.monotonic()
            if now - last_log > 5.0 and (rejects or drops or inject_fail_v4 or inject_fail_v6):
                logger.info(
                    "quic udp/443: %d rejected (ICMP injected), %d dropped "
                    "(inject_fail v4=%d v6=%d) in last 5s",
                    rejects, drops, inject_fail_v4, inject_fail_v6,
                )
                rejects = 0
                drops = 0
                inject_fail_v4 = 0
                inject_fail_v6 = 0
                last_log = now

    def _inject_icmp_port_unreachable(self, original) -> bool:
        """Send a synthetic ICMP port-unreachable back to the origin.

        Returns ``True`` if injection succeeded, ``False`` otherwise.
        The original packet is always dropped (never re-sent) on the
        return path; ``False`` just means no ICMP could be synthesised
        (malformed packet, IPv6 path not supported yet, etc.) so the
        caller counts it as a silent drop.
        """
        import pydivert  # local: Windows-only dependency

        handle = self._quic_handle
        if handle is None:
            return False

        raw = bytes(getattr(original, "raw", b"") or b"")
        if len(raw) < 1:
            return False
        version = (raw[0] >> 4) & 0x0F

        if version == 4:
            icmp_raw = _build_icmpv4_port_unreachable(raw)
        elif version == 6:
            icmp_raw = _build_icmpv6_port_unreachable(raw)
        else:
            return False

        if not icmp_raw:
            return False

        try:
            # ``impostor=True`` tells WinDivert this packet did not
            # originate on the wire; the stack skips its anti-spoof
            # filters and delivers it straight to the input chain.  Our
            # synthesised ICMP carries the *server*'s address in the
            # source field so the kernel treats the reject as coming
            # from the UDP destination and matches it to the right
            # connected socket.  Without the flag the stack silently
            # drops the packet as "source-spoofed" — the exact symptom
            # we observed in realworld.py where logs reported "ICMP
            # injected" but connected UDP probes timed out instead of
            # raising WSAECONNRESET.  With the flag Chromium's QUIC
            # fallback fires within one RTT, so apps that default to
            # HTTP/3 (Discord Electron, Chrome) no longer hang on a
            # 3-10 s HTTP/3 timeout before trying TCP.
            pkt = pydivert.Packet(
                raw=icmp_raw,
                interface=getattr(original, "interface", None),
                direction=pydivert.Direction.INBOUND,
                impostor=True,
            )
        except Exception as exc:  # noqa: BLE001
            logger.info("quic reject packet build failed (v=%d): %s", version, exc)
            return False
        try:
            handle.send(pkt)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.info("quic reject send failed (v=%d): %s", version, exc)
            return False

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
                # Outbound: the ClientHello packet is the only one we
                # reframe; every subsequent C->S segment on a rewritten
                # connection just needs its seq bumped by delta.
                if packet.is_outbound and packet.tcp.dst_port == 443:
                    if trace_enabled():
                        # A "SYN without ACK" is a brand-new connection
                        # attempt; tracing it tells an observer exactly
                        # which tuples Discord (or any app) is opening
                        # before any TLS happens.  Payload-bearing
                        # outbound packets are picked up by the CHLO
                        # branch of _process_outbound and traced there.
                        try:
                            tcp = packet.tcp
                            if bool(getattr(tcp, "syn", False)) and not bool(getattr(tcp, "ack", False)):
                                trace(
                                    "tcp/443 SYN  %s:%s -> %s:%s",
                                    packet.src_addr, packet.src_port,
                                    packet.dst_addr, packet.dst_port,
                                )
                        except Exception:  # noqa: BLE001
                            pass
                    self._process_outbound(packet)
                    continue
                # Inbound: every S->C segment on a rewritten connection
                # needs its ack reduced by delta so the client's TCP
                # stack sees ACKs consistent with what it actually sent.
                if packet.is_inbound and packet.tcp.src_port == 443:
                    self._process_inbound(packet)
                    self._send_with_rewrite_inbound(packet)
                    continue
                handle.send(packet)
            except Exception as exc:  # noqa: BLE001
                logger.debug("dispatch failed: %s", exc)
                try:
                    handle.send(packet)
                except Exception:  # noqa: BLE001
                    pass

    # ------------------------------------------------------------------ seq rewriting
    def _conn_key_outbound(self, packet) -> _ConnKey:
        return _ConnKey(
            client_ip=str(packet.src_addr),
            client_port=int(packet.src_port),
            server_ip=str(packet.dst_addr),
            server_port=int(packet.dst_port),
        )

    def _conn_key_inbound(self, packet) -> _ConnKey:
        return _ConnKey(
            client_ip=str(packet.dst_addr),
            client_port=int(packet.dst_port),
            server_ip=str(packet.src_addr),
            server_port=int(packet.src_port),
        )

    def _register_rewrite(self, key: _ConnKey, delta: int) -> None:
        if delta == 0:
            return
        with self._rewrites_lock:
            self._rewrites[key] = _SeqRewrite(
                delta=delta, created_at=time.monotonic(),
            )
            # Cheap incremental eviction of truly stale entries.
            if len(self._rewrites) > 4096:
                cutoff = time.monotonic() - _REWRITE_TTL_S
                dead = [k for k, v in self._rewrites.items() if v.created_at < cutoff]
                for k in dead:
                    self._rewrites.pop(k, None)

    def _drop_rewrite(self, key: _ConnKey) -> None:
        with self._rewrites_lock:
            self._rewrites.pop(key, None)

    def _rewrite_for(self, key: _ConnKey) -> _SeqRewrite | None:
        with self._rewrites_lock:
            state = self._rewrites.get(key)
            if state is None:
                return None
            now = time.monotonic()
            # Entries idle for longer than the TTL are dropped here;
            # otherwise we refresh the timestamp so an actively-used
            # long-lived connection (WebSocket, gRPC stream, …) keeps
            # its rewrite state for as long as packets flow on it.
            if now - state.created_at > _REWRITE_TTL_S:
                self._rewrites.pop(key, None)
                return None
            state.created_at = now
            return state

    def _send_with_rewrite_outbound(self, packet) -> None:
        """C->S path for non-CHLO packets.  If this 4-tuple has an
        active rewrite, bump seq by delta before sending.  Drop the
        state on FIN/RST so teardown packets carry the untouched
        (zero-length) segments of the real TCP stack."""
        handle = self._handle
        if handle is None:
            return
        key = self._conn_key_outbound(packet)
        state = self._rewrite_for(key)
        if state is not None and state.delta:
            try:
                packet.tcp.seq_num = (int(packet.tcp.seq_num) + state.delta) & 0xFFFFFFFF
            except Exception as exc:  # noqa: BLE001
                logger.debug("seq rewrite (out) failed: %s", exc)
        try:
            handle.send(packet)
        finally:
            if state is not None and (
                bool(getattr(packet.tcp, "fin", False))
                or bool(getattr(packet.tcp, "rst", False))
            ):
                self._drop_rewrite(key)

    def _send_with_rewrite_inbound(self, packet) -> None:
        """S->C path.  If this 4-tuple has an active rewrite, shrink
        ack by delta so the client's TCP stack sees ACKs for the
        amount *it* actually transmitted."""
        handle = self._handle
        if handle is None:
            return
        key = self._conn_key_inbound(packet)
        state = self._rewrite_for(key)
        if state is not None and state.delta:
            try:
                packet.tcp.ack_num = (int(packet.tcp.ack_num) - state.delta) & 0xFFFFFFFF
            except Exception as exc:  # noqa: BLE001
                logger.debug("ack rewrite (in) failed: %s", exc)
        try:
            handle.send(packet)
        finally:
            if state is not None and (
                bool(getattr(packet.tcp, "fin", False))
                or bool(getattr(packet.tcp, "rst", False))
            ):
                self._drop_rewrite(key)

    # ------------------------------------------------------------------ outbound

    def _process_outbound(self, packet) -> None:
        payload = bytes(packet.payload or b"")
        handle = self._handle
        if handle is None:
            return

        # Non-ClientHello C->S packet: may belong to a connection whose
        # initial CHLO we already reframed, in which case we must rewrite
        # its seq number.  Otherwise pass through untouched.
        if not payload or not looks_like_client_hello(payload):
            self._send_with_rewrite_outbound(packet)
            return

        # Multi-segment ClientHello: the record header claims N bytes of
        # payload but this TCP segment only carries M < N of them — the
        # rest will arrive in subsequent packets.  Reframing a partial
        # record as two fixed-length records would leave the second
        # record's length header claiming fewer bytes than will actually
        # follow on the wire, so the server's TLS parser would treat the
        # trailing bytes as the start of a new record (garbage content
        # type) and emit an alert or RST.  Modern browsers with
        # post-quantum ``key_share`` (Firefox NSS, Chromium BoringSSL)
        # and the Electron shell used by Discord routinely produce
        # 2 KB+ ClientHellos that are split across two TCP segments,
        # so this path is hit constantly in practice.  The safe fix is
        # to pass the packet through untouched and let the record
        # traverse the DPI box intact; the userspace proxy on Linux
        # reframes end-to-end instead, and the packet shaper cannot
        # reproduce that without per-connection CH reassembly state.
        try:
            claimed_record_len = int.from_bytes(payload[3:5], "big")
        except Exception:  # noqa: BLE001
            claimed_record_len = -1
        if claimed_record_len >= 0 and 5 + claimed_record_len > len(payload):
            logger.debug(
                "multi-segment CH (record claims %dB, packet carries %dB); "
                "passthrough to preserve TLS record framing",
                claimed_record_len, len(payload) - 5,
            )
            if trace_enabled():
                trace(
                    "tcp/443 CHLO multi-seg passthrough "
                    "%s:%s -> %s:%s record=%dB carried=%dB",
                    packet.src_addr, packet.src_port,
                    packet.dst_addr, packet.dst_port,
                    claimed_record_len, len(payload) - 5,
                )
            self._send_with_rewrite_outbound(packet)
            return

        view = parse_client_hello(payload)
        sni = (view.sni or "").lower()

        # A ClientHello with no SNI can't be matched by any SNI-based DPI
        # filter, so reframing it would only add on-wire bytes and force
        # us to maintain TCP seq-rewrite state for a connection that
        # needed no protection in the first place.  This path matters:
        # the local DoH stub uses ``server_hostname=None`` when talking
        # to public resolvers by IP, and its queries must stay un-shaped
        # so they remain short-lived and reliable even under heavy
        # concurrent Windows telemetry traffic.
        if not sni:
            if trace_enabled():
                trace(
                    "tcp/443 CHLO no-SNI passthrough %s:%s -> %s:%s len=%dB",
                    packet.src_addr, packet.src_port,
                    packet.dst_addr, packet.dst_port, len(payload),
                )
            self._send_with_rewrite_outbound(packet)
            return

        strategy = self._select_strategy(sni)
        if trace_enabled():
            cached = self._cache.get(sni)
            trace(
                "tcp/443 CHLO sni=%s %s:%s -> %s:%s len=%dB "
                "strategy=%s (cache=%s)",
                sni,
                packet.src_addr, packet.src_port,
                packet.dst_addr, packet.dst_port,
                len(payload), strategy.label(),
                "hit" if cached is not None else "miss",
            )

        # Optimistic parallel discovery: if this SNI has never been
        # probed, kick a race of every fallback strategy in the
        # background *now*, in parallel with the default attempt we're
        # about to inject.  If the default happens to work the racer
        # reaches the same conclusion cheaply; if the default fails the
        # cache is already warm by the time the browser retries, so the
        # user sees at most one failed connection instead of the
        # previous "RST → kick serial discovery → wait 5-15 s" loop.
        # `_maybe_kick_discovery` is internally TTL-gated, so a burst
        # of retries from the same SNI fires only one probe.
        if self._cache.get(sni) is None:
            try:
                dst_ip = str(packet.dst_addr)
                dst_port = int(packet.dst_port)
                self._maybe_kick_discovery(sni, dst_ip, dst_port)
            except Exception as exc:  # noqa: BLE001
                logger.debug("optimistic discovery kick failed: %s", exc)

        plan = build_plan(payload, view, strategy)

        # A plan that yields a single fragment is a no-op at the packet
        # layer; don't pay the cost of rebuilding the packet.
        if len(plan.fragments) < 2:
            if trace_enabled():
                trace(
                    "tcp/443 CHLO passthrough sni=%s strategy=%s (plan=1 frag)",
                    sni, strategy.label(),
                )
            self._send_with_rewrite_outbound(packet)
            self._track(packet, sni, strategy.label())
            return

        expected_delta = _record_delta(strategy)
        total = sum(len(f) for f in plan.fragments)
        expected_total = len(payload) + expected_delta
        if total != expected_total:
            logger.debug(
                "strategy %s produced %dB != expected %dB (payload=%dB delta=%dB); passthrough",
                strategy.label(), total, expected_total, len(payload), expected_delta,
            )
            if trace_enabled():
                trace(
                    "tcp/443 CHLO size-mismatch passthrough sni=%s strategy=%s "
                    "(plan=%dB expected=%dB)",
                    sni, strategy.label(), total, expected_total,
                )
            self._send_with_rewrite_outbound(packet)
            return

        try:
            self._inject_fragments(packet, plan.fragments)
        except Exception as exc:  # noqa: BLE001
            logger.debug("inject failed (%s); passthrough", exc)
            if trace_enabled():
                trace(
                    "tcp/443 CHLO inject FAIL sni=%s strategy=%s err=%s (passthrough)",
                    sni, strategy.label(), exc,
                )
            self._send_with_rewrite_outbound(packet)
            return

        if trace_enabled():
            trace(
                "tcp/443 CHLO injected sni=%s strategy=%s frags=%d delta=%dB",
                sni, strategy.label(), len(plan.fragments), expected_delta,
            )

        if expected_delta:
            self._register_rewrite(
                self._conn_key_outbound(packet), expected_delta,
            )
        self._track(packet, sni, strategy.label())

    def _inject_fragments(self, original, fragments: tuple[bytes, ...]) -> None:
        """Re-inject *fragments* as ``len(fragments)`` distinct packets.

        The first fragment reuses the original TCP sequence number; each
        subsequent fragment advances by the number of bytes already sent.
        ACK number, window and flags are preserved — the PSH flag is
        cleared on all but the last fragment so the receiver re-coalesces
        naturally.
        """
        import pydivert  # local import: pydivert is a Windows-only dep

        handle = self._handle
        if handle is None:
            return

        base_seq = int(original.tcp.seq_num) & 0xFFFFFFFF
        had_psh = bool(getattr(original.tcp, "psh", False))
        cursor = base_seq

        # pydivert's Packet constructor takes ``interface`` (a
        # ``(if_idx, sub_if_idx)`` tuple identifying the NIC the packet
        # arrived on) and ``direction`` (INBOUND/OUTBOUND).  Both are
        # exposed on the captured packet we were handed.
        interface = getattr(original, "interface", None)
        direction = getattr(original, "direction", None)

        for idx, frag in enumerate(fragments):
            if not frag:
                continue
            is_last = idx == len(fragments) - 1
            # Clone raw bytes so each fragment has its own backing
            # buffer; mutating ``payload`` recomputes IP total length
            # and the TCP/IP checksums on the next ``handle.send``.
            pkt = pydivert.Packet(
                raw=bytes(original.raw),
                interface=interface,
                direction=direction,
            )
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
            if trace_enabled():
                # Only trace untracked RSTs; an untracked ACK-only
                # packet here is every S->C segment on connections we
                # never reframed, which would drown the log.
                if bool(getattr(packet.tcp, "rst", False)):
                    trace(
                        "tcp/443 RST  %s:%s <- %s:%s (no tracked CHLO)",
                        key.client_ip, key.client_port,
                        key.server_ip, key.server_port,
                    )
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
            if trace_enabled():
                trace(
                    "tcp/443 RST  sni=%s strategy=%s %s:%s <- %s:%s (DPI reset)",
                    state.sni, state.strategy_label,
                    key.client_ip, key.client_port,
                    key.server_ip, key.server_port,
                )
            self._maybe_kick_discovery(state.sni, key.server_ip, key.server_port)
            return

        if len(payload) >= 2 and payload[0] == 0x16 and payload[1] == 0x03:
            self._cache.record_success(state.sni, state.strategy_label)
            with self._pending_lock:
                self._pending.pop(key, None)
            logger.debug(
                "strategy ok sni=%s strategy=%s",
                state.sni, state.strategy_label,
            )
            if trace_enabled():
                trace(
                    "tcp/443 ServerHello sni=%s strategy=%s len=%dB",
                    state.sni, state.strategy_label, len(payload),
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
            if trace_enabled():
                trace(
                    "tcp/443 non-TLS reply sni=%s strategy=%s head=%s",
                    state.sni, state.strategy_label, payload[:4].hex(),
                )
            self._maybe_kick_discovery(state.sni, key.server_ip, key.server_port)
        elif trace_enabled() and payload and payload[0] == 0x15:
            trace(
                "tcp/443 TLS alert sni=%s strategy=%s head=%s (DPI middlebox?)",
                state.sni, state.strategy_label, payload[:6].hex(),
            )

    # ------------------------------------------------------------------ active discovery
    #
    # The packet shaper sees the outcome of the *current* connection
    # (RST, non-TLS reply, or TLS handshake).  On failure, passive
    # learning alone is not enough: the next connection from the same
    # SNI would try the same default again and fail the same way.
    #
    # Instead, on a passive failure we kick off a one-shot background
    # probe that behaves like Linux's in-proxy :func:`discover`: open
    # direct TCP sockets to the target IP, try each fallback strategy
    # in order, and record the first one whose upstream reply begins
    # with a valid TLS record.  The winning label is written to the
    # shared :class:`StrategyCache`, so the *next* real browser
    # connection to the same SNI picks it up via :meth:`_select_strategy`
    # and avoids the reset entirely.
    #
    # We only probe once per SNI per _DISCOVERY_TTL_S so a burst of
    # failed browser retries against a blocked host doesn't snowball
    # into N parallel probes.
    def _maybe_kick_discovery(self, sni: str, dest_ip: str, dest_port: int) -> None:
        if not sni or not self._fallbacks:
            return
        now = time.monotonic()
        with self._discovery_lock:
            deadline = self._discovery_inflight.get(sni, 0.0)
            if deadline > now:
                return
            self._discovery_inflight[sni] = now + _DISCOVERY_TTL_S
        t = threading.Thread(
            target=self._run_discovery,
            args=(sni, dest_ip, dest_port),
            name=f"whydpi-discover-{sni[:32]}",
            daemon=True,
        )
        t.start()

    def _run_discovery(self, sni: str, dest_ip: str, dest_port: int) -> None:
        try:
            hello = build_minimal_client_hello(sni)
            view = parse_client_hello(hello)
            candidates = order_candidates(
                None, self._raw_default, self._raw_fallbacks
            )
            logger.info(
                "active discovery sni=%s dest=%s:%d candidates=%s (parallel race)",
                sni, dest_ip, dest_port,
                ",".join(s.label() for s in candidates),
            )
            result = discover_parallel(
                dest_ip=dest_ip,
                dest_port=dest_port,
                hello_bytes=hello,
                hello_view=view,
                candidates=candidates,
                proxy_mark=0,  # unused on Windows (no SO_MARK)
                timeout_s=self._probe_timeout_s,
                success_min_bytes=self._success_min_bytes,
                # Reject TLS alerts (0x15) as "success".  A real peer,
                # replaying the user's real ClientHello, replies with a
                # ServerHello record (0x16); a ``0x15`` alert is the
                # classic shape of a DPI middlebox tearing the
                # connection down after it reassembled the SNI.  If we
                # accepted it here we would cache the "working"
                # strategy that reaches the middlebox, not the origin,
                # and every subsequent browser connection would hit the
                # same MITM — with a plausible-looking but wrong
                # certificate.  Strict ``0x16``-only acceptance costs
                # us nothing against legitimate origins (they always
                # ServerHello on a valid CH) and blocks this whole
                # class of silent-poisoning bug.
                accept_alert=False,
            )
            if result.upstream is not None:
                try:
                    result.upstream.close()
                except OSError:
                    pass
            if result.strategy is None:
                logger.warning(
                    "active discovery sni=%s: NO STRATEGY  attempts=%s",
                    sni,
                    ",".join(f"{lbl}:{reason}" for lbl, reason in result.attempts),
                )
                return
            # Write the raw-layer label (e.g. "record:sni-mid") to the
            # cache so a future _select_strategy re-applies the remap and
            # the shaper fragments packets identically to this probe.
            winning_label = result.strategy.label()
            self._cache.record_success(sni, winning_label)
            logger.info(
                "active discovery sni=%s: %s  attempts=%s",
                sni, winning_label,
                ",".join(f"{lbl}:{reason}" for lbl, reason in result.attempts),
            )
        except Exception:  # noqa: BLE001
            logger.exception("active discovery sni=%s crashed", sni)
        finally:
            with self._discovery_lock:
                # Clear the in-flight marker early on success so the
                # TTL only gates *failed* probes (success means the
                # cache has a winner, we don't need to re-probe).
                self._discovery_inflight.pop(sni, None)


# ---------------------------------------------------------------------------
# ICMPv4 synthesis — used by the QUIC reject path.
# ---------------------------------------------------------------------------
#
# RFC 792: a Destination-Unreachable / Port-Unreachable message carries
# the *original* IP header plus the first eight bytes of the offending
# datagram as its payload, preceded by an 8-byte ICMP header.  The
# containing IPv4 header's source address is the UDP destination the
# client aimed at (so the reject looks authentic); its destination
# address is the client's own IP.  Checksums are re-computed from
# scratch to avoid depending on WinDivert's header-rewrite bookkeeping.

def _inet4_checksum(data: bytes) -> int:
    """RFC 1071 one's-complement 16-bit checksum over *data*."""
    total = 0
    length = len(data)
    # Pairwise big-endian sum.
    for i in range(0, length - 1, 2):
        total += (data[i] << 8) | data[i + 1]
    if length & 1:
        total += data[-1] << 8
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _build_icmpv4_port_unreachable(orig_raw: bytes) -> bytes:
    """Return a complete IPv4 + ICMP port-unreachable packet for *orig_raw*.

    ``orig_raw`` is the raw outbound IPv4 packet we just captured; we
    peel off its IP header and first 8 bytes of payload to embed them
    as the ICMP "offending datagram" field.  Returns an empty bytes
    object on any structural error so callers treat it as "no ICMP,
    fall back to silent drop".
    """
    if len(orig_raw) < 20:
        return b""
    ihl = (orig_raw[0] & 0x0F) * 4
    if ihl < 20 or ihl > len(orig_raw):
        return b""
    # Per RFC 792 the data field carries "the internet header plus the
    # first 64 bits of the original datagram's data".  Embedding the
    # source UDP header (8 bytes) is what lets the receiving TCP/IP
    # stack match this ICMP to the correct socket.
    wanted_payload = 8
    original_ip_header = orig_raw[:ihl]
    original_first8 = orig_raw[ihl:ihl + wanted_payload]
    if len(original_first8) < wanted_payload:
        # Short datagram — still emit ICMP with whatever we have; most
        # stacks handle a truncated quote gracefully.
        original_first8 = original_first8.ljust(wanted_payload, b"\x00")

    icmp_data = original_ip_header + original_first8

    # ICMP header: Type=3 (Dest Unreachable), Code=3 (Port Unreachable),
    # Checksum (filled below), Unused=0.
    icmp_no_cksum = _struct.pack("!BBHI", 3, 3, 0, 0) + icmp_data
    icmp_cksum = _inet4_checksum(icmp_no_cksum)
    icmp = _struct.pack("!BBHI", 3, 3, icmp_cksum, 0) + icmp_data

    orig_src = orig_raw[12:16]  # client IP
    orig_dst = orig_raw[16:20]  # UDP server IP

    try:
        # Sanity: reject anything that isn't a plain unicast IPv4
        # address pair; we don't want to synthesise ICMP from a
        # multicast or link-local source.
        ipaddress.IPv4Address(_socket.inet_ntoa(orig_dst))
        ipaddress.IPv4Address(_socket.inet_ntoa(orig_src))
    except (ValueError, OSError):
        return b""

    total_len = 20 + len(icmp)
    # Ident=0, flags+frag=0, TTL=64, proto=1 (ICMP).  Many stacks use
    # a non-zero IP id for locally-generated ICMP; zero is also valid
    # (RFC 6864) and spares us a counter.
    ip_header_no_cksum = (
        _struct.pack("!BBHHHBBH", 0x45, 0, total_len, 0, 0, 64, 1, 0)
        + orig_dst  # source = the UDP destination
        + orig_src  # destination = the original sender
    )
    ip_cksum = _inet4_checksum(ip_header_no_cksum)
    ip_header = (
        _struct.pack("!BBHHHBBH", 0x45, 0, total_len, 0, 0, 64, 1, ip_cksum)
        + orig_dst
        + orig_src
    )
    return ip_header + icmp


# ---------------------------------------------------------------------------
# ICMPv6 synthesis — IPv6 QUIC reject path.
# ---------------------------------------------------------------------------
#
# RFC 4443: a Destination-Unreachable / Port-Unreachable message (Type 1
# Code 4) carries "as much of the invoking packet as possible without the
# ICMPv6 error message exceeding the minimum IPv6 MTU" (1280 bytes).  For
# QUIC we only need enough of the original datagram for the kernel to
# locate the offending socket — 40-byte IPv6 header + 8-byte UDP header
# is sufficient.  The checksum is a standard internet checksum over a
# pseudo-header (src||dst||upper-layer-length||zero||next-header=58)
# followed by the ICMPv6 message itself.


def _build_icmpv6_port_unreachable(orig_raw: bytes) -> bytes:
    """Return a complete IPv6 + ICMPv6 port-unreachable packet for *orig_raw*.

    Returns an empty bytes object on any structural error so callers
    treat it as "no ICMPv6, fall back to silent drop".
    """
    if len(orig_raw) < 40:
        return b""
    if ((orig_raw[0] >> 4) & 0x0F) != 6:
        return b""
    # Quote fixed IPv6 header + first 8 bytes of UDP header (enough
    # for the kernel to match the sending socket on its 4-tuple).
    wanted_payload = 8
    original_ip_header = orig_raw[:40]
    original_first8 = orig_raw[40:40 + wanted_payload]
    if len(original_first8) < wanted_payload:
        original_first8 = original_first8.ljust(wanted_payload, b"\x00")
    quote = original_ip_header + original_first8

    orig_src = orig_raw[8:24]   # client IPv6 address
    orig_dst = orig_raw[24:40]  # UDP server IPv6 address

    # ICMPv6 message: Type=1 (Destination Unreachable), Code=4
    # (Port Unreachable), Checksum (filled below), Unused=0.
    icmp_body = _struct.pack("!BBHI", 1, 4, 0, 0) + quote

    # Pseudo-header for checksum.  Per RFC 2460 §8.1 / RFC 4443 §2.3,
    # the "upper-layer length" is the ICMPv6 message length (header +
    # data); "next header" used for the pseudo-header is 58 (ICMPv6),
    # which is different from the actual IPv6 Next Header field used
    # for routing.
    upper_len = len(icmp_body)
    pseudo = (
        orig_dst               # source of the synthesised packet
        + orig_src             # destination (original sender)
        + _struct.pack("!I", upper_len)
        + b"\x00\x00\x00"
        + b"\x3a"              # next header = 58 (ICMPv6)
    )
    cksum = _inet4_checksum(pseudo + icmp_body)
    icmp = _struct.pack("!BBHI", 1, 4, cksum, 0) + quote

    # IPv6 header: version=6, traffic class=0, flow label=0,
    # payload length = ICMPv6 length, next header = 58, hop limit = 64.
    ipv6_header = (
        _struct.pack(
            "!IHBB",
            (6 << 28),         # version 6, tclass=0, flow=0
            upper_len,         # payload length
            58,                # next header = ICMPv6
            64,                # hop limit
        )
        + orig_dst             # source = UDP destination
        + orig_src             # destination = original sender
    )
    return ipv6_header + icmp
