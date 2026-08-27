# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""TTL-aware in-memory DNS answer cache.

Design
======
Our DoH-forwarding path (Linux stub, Windows packet hijacker) incurs a
~50-200 ms TLS round-trip per cold query.  A single browser page load
issues 20-80 distinct DNS questions in parallel bursts, so even with a
perfectly-sized connection pool the *aggregate* DoH cost dominates
page latency on fresh SNIs — exactly the "content-heavy pages feel
sluggish right after the engine starts" symptom reported in the wild.

A transport-layer resolver cache (``systemd-resolved`` on Linux,
``Dnscache`` on Windows) already exists upstream, but both have
cache-miss windows after fresh boots, flushes, or — on Windows —
for apps that bring their own resolver (Chrome built-in DoH, Go
``net.Resolver`` with ``PreferGo=true``, some VPN stacks) and bypass
the OS cache entirely.  Every one of those still emits UDP/53 on the
wire, every one of those still hits our hijacker, so we're the
bottleneck when the OS cache can't help.

This module is a minimalist, standards-respectful answer cache sitting
in front of the DoH forwarder:

* **Key** — ``(lower-case qname, qtype, qclass)`` extracted from the
  DNS question section.  Case-insensitive per RFC 1035 §2.3.3.
* **Value** — the full on-wire DNS response as stored; on hit the
  caller's transaction id is stamped into the first two bytes so
  clients still see a response matching the query they just sent.
* **TTL** — minimum TTL across all RRs in the response, clamped to
  ``[_MIN_TTL_S, _MAX_TTL_S]``.  Empty-answer / error responses are
  cached briefly (``_NEG_TTL_S``) to dampen retry storms without
  contradicting short-TTL records.
* **Eviction** — soft cap at ``_MAX_ENTRIES``; on overflow we drop
  already-expired entries first, then the oldest-by-deadline entries.

Privacy
-------
The cache lives only in process RAM, is never persisted to disk, and
is wiped by :meth:`DnsCache.wipe` on every engine shutdown alongside
the strategy cache — so "service stopped" really does mean "traces
gone".  No domain name is ever logged.
"""

from __future__ import annotations

import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable


# Clamp bounds for positive answers.  A 0-TTL record exists (mail exchangers
# with DNS-based load balancing, some CDNs) but caching it for 0 seconds is
# equivalent to not caching at all and re-introduces the slow cold path we
# built this cache to fix.  30 s is short enough that a real DNS change
# propagates within a browser tab reload.
_MIN_TTL_S = 30.0
# Upper bound keeps long-TTL records (ten-minute CDN answers) from persisting
# unreasonably long in a process that may run for days; also bounds the
# memory footprint.
_MAX_TTL_S = 600.0
# Short negative-cache window: enough to collapse a browser retry burst on a
# NXDOMAIN or SERVFAIL without trapping a real transient upstream hiccup.
_NEG_TTL_S = 10.0
# 4 k entries * ~512 B avg response * 2 overhead ≈ 4 MB peak — well within
# the footprint budget for a tray application.
_MAX_ENTRIES = 4096


@dataclass
class _Entry:
    """One cached DNS response with absolute expiry deadline."""
    wire_template: bytes
    expires_at: float


def _parse_qname(wire: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name starting at ``offset``.

    Returns ``(lower-case dotted name, offset_after_name)``.  Questions
    don't use pointer compression in practice; if we encounter one we
    treat it as a terminator — losing potential cache hits but never
    producing a wrong hit.
    """
    labels: list[str] = []
    i = offset
    end = len(wire)
    while i < end:
        length = wire[i]
        if length == 0:
            return ".".join(labels).lower(), i + 1
        if length & 0xC0:
            return ".".join(labels).lower(), i + 2
        i += 1
        if i + length > end:
            raise ValueError("truncated qname label")
        labels.append(wire[i:i + length].decode("ascii", errors="replace"))
        i += length
    raise ValueError("unterminated qname")


def _question_key(wire: bytes) -> tuple[str, int, int] | None:
    """Extract ``(qname, qtype, qclass)`` from a DNS query or response.

    Returns ``None`` if the message is malformed or carries no question.
    """
    if len(wire) < 12:
        return None
    qdcount = struct.unpack_from("!H", wire, 4)[0]
    if qdcount < 1:
        return None
    try:
        qname, after = _parse_qname(wire, 12)
        if after + 4 > len(wire):
            return None
        qtype, qclass = struct.unpack_from("!HH", wire, after)
        return qname, int(qtype), int(qclass)
    except (ValueError, struct.error, IndexError):
        return None


def _skip_name(wire: bytes, offset: int) -> int:
    """Advance past a (possibly-compressed) DNS name in a response."""
    end = len(wire)
    i = offset
    while i < end:
        b = wire[i]
        if b == 0:
            return i + 1
        if b & 0xC0:
            return i + 2
        i += 1 + b
    raise ValueError("unterminated name in response")


def _min_ttl(response: bytes) -> float | None:
    """Minimum TTL across all RRs in *response*, or ``None`` if the
    response parses but carries no RRs (SOA-only negative answers fall
    into this branch and get short negative caching)."""
    if len(response) < 12:
        return None
    _, _, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", response, 0)
    pos = 12
    try:
        for _ in range(qdcount):
            _, pos = _parse_qname(response, pos)
            pos += 4  # qtype + qclass
        ttls: list[int] = []
        for _ in range(ancount + nscount + arcount):
            pos = _skip_name(response, pos)
            if pos + 10 > len(response):
                return None
            _, _, ttl, rdlen = struct.unpack_from("!HHIH", response, pos)
            ttls.append(int(ttl))
            pos += 10 + int(rdlen)
        if not ttls:
            return None
        return float(min(ttls))
    except (struct.error, ValueError, IndexError):
        return None


class DnsCache:
    """Thread-safe, TTL-respectful DNS answer cache.

    Only the answer bytes are stored; the caller's transaction id is
    overlaid onto the template at lookup time so clients never see a
    stale id.
    """

    def __init__(self, *, max_entries: int = _MAX_ENTRIES) -> None:
        self._entries: dict[tuple[str, int, int], _Entry] = {}
        self._lock = threading.Lock()
        self._max = max(1, int(max_entries))
        # In-flight deduplication: when a cold query arrives we register
        # its key in ``_inflight`` before issuing the DoH request; any
        # subsequent caller for the same ``(qname, qtype, qclass)`` waits
        # on the attached :class:`threading.Event` instead of issuing a
        # duplicate upstream query.  Parallel page-load bursts routinely
        # ask for the same A + AAAA records from dozens of connections
        # at once; without this guard each of them races to the DoH
        # resolver, defeats the connection pool, and adds hundreds of
        # milliseconds of latency to every worker.
        self._inflight: dict[tuple[str, int, int], threading.Event] = {}
        self._inflight_lock = threading.Lock()

    def get(self, query_wire: bytes) -> bytes | None:
        """Return a response matching *query_wire* or ``None``."""
        key = _question_key(query_wire)
        if key is None or len(query_wire) < 2:
            return None
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry.expires_at <= now:
                self._entries.pop(key, None)
                return None
            template = entry.wire_template
        if len(template) < 2:
            return None
        # Overlay the caller's transaction id.
        return query_wire[:2] + template[2:]

    def put(self, query_wire: bytes, response_wire: bytes) -> None:
        """Cache *response_wire* as the answer to *query_wire*.

        Silently ignored on malformed inputs.
        """
        key = _question_key(query_wire)
        if key is None or len(response_wire) < 12:
            return
        ttl = _min_ttl(response_wire)
        if ttl is None:
            ttl = _NEG_TTL_S
        else:
            ttl = max(_MIN_TTL_S, min(ttl, _MAX_TTL_S))
        deadline = time.monotonic() + ttl
        with self._lock:
            if len(self._entries) >= self._max:
                self._evict_locked()
            self._entries[key] = _Entry(
                wire_template=bytes(response_wire),
                expires_at=deadline,
            )

    def resolve(
        self,
        query_wire: bytes,
        compute: Callable[[bytes], bytes],
        *,
        wait_timeout_s: float = 5.0,
    ) -> bytes:
        """Cache-and-dedup resolver wrapper.

        Fast-path: cached hit → return synthesised response immediately.

        Cold path: if no other thread is already resolving this key,
        *this* thread becomes the leader — it calls ``compute(query_wire)``,
        stores the result, and signals the waiters.  Meanwhile any other
        thread with the same key blocks on a per-key :class:`threading.Event`
        for up to ``wait_timeout_s`` seconds, then re-checks the cache;
        on follower timeout it falls back to issuing its own ``compute``
        call so a slow leader never pins the whole pool.

        Returns an empty byte string only if *both* the leader and the
        fallback compute calls fail.
        """
        cached = self.get(query_wire)
        if cached is not None:
            return cached
        key = _question_key(query_wire)
        if key is None:
            return compute(query_wire)

        leader_event: threading.Event | None = None
        follower_event: threading.Event | None = None
        with self._inflight_lock:
            existing = self._inflight.get(key)
            if existing is None:
                leader_event = threading.Event()
                self._inflight[key] = leader_event
            else:
                follower_event = existing

        if follower_event is not None:
            # Second arrival for the same question — wait for the leader
            # to populate the cache, then re-check.  On timeout we fall
            # through to a direct compute so a stuck leader doesn't
            # stall every peer forever.
            follower_event.wait(timeout=wait_timeout_s)
            cached = self.get(query_wire)
            if cached is not None:
                return cached
            # Leader gave up or failed; resolve ourselves.
            try:
                return compute(query_wire)
            except Exception:  # noqa: BLE001
                return b""

        # Leader path: produce the answer, populate the cache, signal.
        assert leader_event is not None
        try:
            response = compute(query_wire)
        except Exception:  # noqa: BLE001
            response = b""
        if response:
            self.put(query_wire, response)
        with self._inflight_lock:
            self._inflight.pop(key, None)
        leader_event.set()
        return response

    def wipe(self) -> None:
        """Drop every cached entry.  Called on engine shutdown."""
        with self._lock:
            self._entries.clear()
        with self._inflight_lock:
            # Wake any lingering waiters so shutdown doesn't strand them.
            for evt in self._inflight.values():
                evt.set()
            self._inflight.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    # Internal -------------------------------------------------------

    def _evict_locked(self) -> None:
        """Make room for a new entry.  Caller holds ``self._lock``."""
        now = time.monotonic()
        expired = [k for k, e in self._entries.items() if e.expires_at <= now]
        for k in expired:
            self._entries.pop(k, None)
        if len(self._entries) < self._max:
            return
        # Still full: drop the 5 % nearest to expiry.
        ordered = sorted(self._entries.items(), key=lambda kv: kv[1].expires_at)
        drop_count = max(1, len(ordered) // 20)
        for k, _ in ordered[:drop_count]:
            self._entries.pop(k, None)
