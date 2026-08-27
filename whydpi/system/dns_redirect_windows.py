# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Windows packet-layer DNS redirector — the Linux ``iptables DNAT`` analogue.

Design
======
On Linux the DNS redirect is a single packet-layer primitive:

.. code-block:: text

    iptables -t nat -A OUTPUT -p udp --dport 53 \\
        -j DNAT --to-destination 127.0.0.53:53

The kernel rewrites the destination at the netfilter layer — apps never
see it, the OS resolver config is not touched, and the moment the rule
disappears the user's traffic flows natural again.  This is what makes
the Linux tray feel instant: no network reset, no adapter fiddling, no
per-app opt-in.

Windows has no ``REDIRECT``/``DNAT`` nat target.  What it *does* have,
however, is `WinDivert`, a signed Microsoft kernel-mode driver that can
intercept, modify, drop, and inject IP packets at the network layer
without touching any user-mode configuration.  That is enough to
replicate the Linux primitive *exactly*.

This module implements an in-process DNS hijacker:

1.  A WinDivert handle captures every outbound UDP packet whose
    destination port is 53 (both IPv4 and IPv6).
2.  The payload — a raw DNS wire query — is handed off to a worker pool
    that forwards it to a public resolver over DoH (the same
    :class:`~whydpi.net.dns.DoHClient` the Linux stub uses, so TLS
    fragmentation inherits from our shaper automatically).
3.  The DoH answer is framed back into a synthetic UDP packet whose
    source address/port is the original destination (making the reply
    look identical to one the ISP's resolver would have sent) and
    injected back inbound through the same driver handle.
4.  The original outbound packet is dropped.  If DoH fails (worker
    pool saturated, upstream unreachable, malformed query, etc.) the
    original packet is re-injected unchanged so the user is never left
    without DNS.

Why this beats the previous three-layer approach
------------------------------------------------
The prior design reconfigured adapter DNS via ``netsh``, installed
NRPT catch-all rules, and added a Windows Firewall egress block for
UDP/TCP :53.  That combination had three compounding problems:

* ``netsh`` mutates persisted OS state.  A crash between
  ``configure`` and ``restore`` leaves the user without a working
  resolver until they run ``whydpi stop`` manually.
* NRPT is evaluated by the Windows DNS Client service; apps that
  bring their own resolver (Chrome built-in DoH, Firefox TRR, Go
  programs calling ``net.Resolver`` with ``PreferGo=true``, some
  VPN clients) bypass it entirely.
* The firewall egress block was added to plug those leaks, but it
  is indiscriminate: if the stub fails to answer for *any* reason
  (port in use, admin token lost, race with the DNS Client service)
  the block remains active and every resolver query in the system
  simply times out.  That is the "hiçbir siteye erişemedim"
  symptom.

Intercepting at the packet layer eliminates all three:

* There is no persisted OS state to restore.  Close the handle and
  traffic flows natural again the same instant.
* Apps that bring their own resolver still send UDP/53 packets down
  the wire (or use DoH over TCP/443, which our shaper handles on the
  TLS layer) — either way we see the traffic.
* No firewall rule is ever installed.  A crash or abrupt exit leaves
  the system in a known-good state, because there is nothing to roll
  back.

IPv6 support
------------
The WinDivert filter enrolls both ``ip`` and ``ipv6`` families; the
packet struct exposes src/dst as strings regardless of family, so the
reply synthesiser is address-family-agnostic.  The reply packet keeps
the same family as the query.

TCP/53 is intentionally not intercepted here.  Windows clients fall
back to TCP/53 only when the UDP reply is truncated (TC flag set); our
DoH answers are always non-truncated, so the TCP/53 path is never
exercised from the client side.  Zero-need paths are out of scope for
a minimal, auditable bypass.
"""

from __future__ import annotations

import logging
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from ..net.dns import DoHClient
from ..net.dns_cache import DnsCache
from ._trace import format_dns_question, trace, trace_enabled


logger = logging.getLogger(__name__)


# Match any outbound UDP packet, v4 or v6, whose destination is port 53.
# We deliberately use ``outbound`` rather than a second filter for
# inbound: all replies we deliver come from ``handle.send`` with
# ``direction=INBOUND``, and WinDivert never re-captures those.
_FILTER = "(ip or ipv6) and outbound and udp and udp.DstPort == 53"


class PacketDnsHijacker:
    """Intercept outbound UDP/53 and answer from a DoH upstream.

    A TTL-aware in-memory cache (shared across all workers) sits in
    front of the DoH forwarder: bursty queries for the same hostname
    (common during page loads) are answered from RAM without ever
    touching the upstream resolver.  Cache lifetime is bounded by the
    server-provided TTL and wiped on :meth:`stop`, preserving the
    "service stopped == traces gone" invariant.
    """

    def __init__(
        self,
        *,
        primary: DoHClient,
        fallback: Optional[DoHClient] = None,
        cache: Optional[DnsCache] = None,
        worker_threads: int = 32,
    ) -> None:
        self._primary = primary
        self._fallback = fallback
        self._cache = cache if cache is not None else DnsCache()
        self._pool = ThreadPoolExecutor(
            max_workers=max(1, int(worker_threads)),
            thread_name_prefix="whydpi-dns",
        )
        self._handle = None  # pydivert.WinDivert, opened lazily in start()
        self._thread: threading.Thread | None = None
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        import sys

        if sys.platform != "win32":
            raise RuntimeError(
                "PacketDnsHijacker is Windows-only; on Linux use iptables DNAT."
            )

        import pydivert  # deferred: Windows-only dep

        self._handle = pydivert.WinDivert(_FILTER)
        self._handle.open()
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, name="whydpi-dns-hijack", daemon=True,
        )
        self._thread.start()
        logger.info(
            "DNS hijacker active (upstream primary=%s fallback=%s workers=%d)",
            getattr(self._primary._endpoint, "ip", "?"),  # type: ignore[attr-defined]
            getattr(self._fallback._endpoint, "ip", None) if self._fallback else "-",  # type: ignore[attr-defined]
            self._pool._max_workers,
        )
        if trace_enabled():
            logger.info(
                "WHYDPI_TRACE=1: per-query DNS events will be emitted at "
                "INFO under whydpi.trace",
            )

    def stop(self) -> None:
        self._running = False
        handle = self._handle
        self._handle = None
        if handle is not None:
            try:
                handle.close()
            except Exception as exc:  # noqa: BLE001
                logger.debug("dns hijacker close: %s", exc)
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        try:
            self._pool.shutdown(wait=False, cancel_futures=True)
        except Exception as exc:  # noqa: BLE001
            logger.debug("dns hijacker pool shutdown: %s", exc)
        # Privacy: no DNS answers outlive the session.  Upstream DoH
        # connections are closed by the engine's shutdown path (it
        # also wipes the strategy cache), so both caches disappear
        # together.
        try:
            self._cache.wipe()
        except Exception as exc:  # noqa: BLE001
            logger.debug("dns cache wipe: %s", exc)
        logger.info("DNS hijacker stopped")

    # ------------------------------------------------------------------
    # Main loop (single thread; dispatches I/O-bound DoH work to pool)
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        handle = self._handle
        if handle is None:
            return
        while self._running:
            try:
                packet = handle.recv()
            except Exception as exc:  # noqa: BLE001
                if self._running:
                    logger.debug("dns hijacker recv failed: %s", exc)
                break
            try:
                self._pool.submit(self._handle_query, packet)
            except RuntimeError:
                # Pool shutting down — forward untouched so the user
                # doesn't see a stalled query in the race between
                # stop() and the final packet.
                self._passthrough(packet)

    # ------------------------------------------------------------------
    # Per-query worker
    # ------------------------------------------------------------------

    def _handle_query(self, packet) -> None:
        try:
            payload = bytes(packet.payload or b"")
            if len(payload) < 12:
                # Not a valid DNS header (id + flags + 4 counts == 12 bytes).
                if trace_enabled():
                    trace(
                        "udp/53 query malformed len=%dB %s:%s -> %s:%s (passthrough)",
                        len(payload),
                        packet.src_addr, packet.src_port,
                        packet.dst_addr, packet.dst_port,
                    )
                self._passthrough(packet)
                return

            if trace_enabled():
                trace(
                    "udp/53 query %s  %s:%s -> %s:%s",
                    format_dns_question(payload),
                    packet.src_addr, packet.src_port,
                    packet.dst_addr, packet.dst_port,
                )

            # Single call handles the cache lookup, the cache store, and
            # in-flight dedup: a burst of parallel queries for the same
            # ``(qname, qtype, qclass)`` collapses onto one DoH RTT
            # instead of racing the upstream resolver N times.
            answer = self._cache.resolve(payload, self._query_doh)
            if not answer or len(answer) < 12:
                if trace_enabled():
                    trace(
                        "udp/53 query %s -> no answer (passthrough to OS resolver)",
                        format_dns_question(payload),
                    )
                self._passthrough(packet)
                return

            self._inject_reply(packet, answer)
        except Exception as exc:  # noqa: BLE001
            logger.debug("dns hijack failed: %s", exc)
            if trace_enabled():
                trace("udp/53 hijack crashed: %s (passthrough)", exc)
            self._passthrough(packet)

    def _query_doh(self, wire: bytes) -> bytes:
        qname = format_dns_question(wire) if trace_enabled() else ""
        for client, label in ((self._primary, "primary"),
                              (self._fallback, "fallback")):
            if client is None:
                continue
            try:
                answer = client.query(wire)
                if trace_enabled():
                    trace(
                        "udp/53 DoH %s ok %s len=%dB",
                        label, qname, len(answer) if answer else 0,
                    )
                return answer
            except Exception as exc:  # noqa: BLE001
                logger.debug("DoH upstream failed: %s", exc)
                if trace_enabled():
                    trace(
                        "udp/53 DoH %s FAIL %s err=%s",
                        label, qname, exc,
                    )
        return b""

    # ------------------------------------------------------------------
    # Packet injection helpers
    # ------------------------------------------------------------------

    def _inject_reply(self, packet, dns_answer: bytes) -> None:
        """Turn the captured query into a synthetic reply and inject it
        back as inbound.  The app's UDP socket sees a standard DNS reply
        coming from the server it originally asked."""
        import pydivert  # local: Windows-only

        handle = self._handle
        if handle is None:
            return

        # Ensure the DNS answer carries the same transaction ID the app
        # sent us.  Upstream DoH preserves it already, but we clamp just
        # in case some exotic resolver rewrites the header.
        query_txid = struct.unpack_from("!H", packet.payload, 0)[0]
        if struct.unpack_from("!H", dns_answer, 0)[0] != query_txid:
            dns_answer = struct.pack("!H", query_txid) + dns_answer[2:]

        # Swap address/port so the reply looks like it came from the
        # resolver the app targeted.  pydivert rewrites headers in place
        # and recalculates IP/UDP checksums on the next ``send()``.
        orig_src_addr = packet.src_addr
        orig_dst_addr = packet.dst_addr
        orig_src_port = int(packet.src_port)
        orig_dst_port = int(packet.dst_port)
        packet.src_addr = orig_dst_addr
        packet.dst_addr = orig_src_addr
        packet.src_port = orig_dst_port
        packet.dst_port = orig_src_port
        packet.payload = dns_answer
        packet.direction = pydivert.Direction.INBOUND

        try:
            handle.send(packet)
            if trace_enabled():
                trace(
                    "udp/53 reply injected %s <- %s:%s len=%dB",
                    packet.dst_addr,
                    packet.src_addr, packet.src_port,
                    len(dns_answer),
                )
        except Exception as exc:  # noqa: BLE001
            logger.debug("dns reply inject failed: %s", exc)
            if trace_enabled():
                trace("udp/53 reply inject FAIL err=%s", exc)

    def _passthrough(self, packet) -> None:
        handle = self._handle
        if handle is None:
            return
        try:
            handle.send(packet)
        except Exception as exc:  # noqa: BLE001
            logger.debug("dns passthrough send failed: %s", exc)
