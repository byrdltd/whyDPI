# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Opt-in packet-layer trace mode for Windows diagnostics.

Enabled by setting ``WHYDPI_TRACE=1`` (or ``true`` / ``yes`` / ``on``) in
the environment before the engine starts.  When on, the WinDivert shaper
and DNS hijacker emit a short INFO-level line for every interesting
event on the wire: outbound TCP/443 SYNs, captured TLS ClientHellos
with their SNI and selected strategy, inbound RSTs, outbound UDP/443
QUIC datagrams and the result of the synthetic ICMP reject, every
DNS query's ``QNAME``/``QTYPE`` and whether it was served from the
cache or went upstream over DoH, and every synthesised DNS reply
injected back inbound.

When the flag is off, :func:`trace_enabled` is a single ``bool`` read
and every call site short-circuits through a cheap ``if`` before
touching any formatter — keeping the fast path allocation-free.

The module is deliberately small and self-contained so it has zero
import-time side effects on Linux and can be dropped wholesale from a
future build without touching any feature code.
"""

from __future__ import annotations

import logging
import os


def _read_flag() -> bool:
    raw = os.environ.get("WHYDPI_TRACE", "")
    return raw.strip().lower() in ("1", "true", "yes", "on")


# Resolved once at import time.  We intentionally *do not* re-read the
# environment on every call: toggling trace mid-session is not a goal,
# and caching lets every trace site boil down to a single boolean load.
_TRACE: bool = _read_flag()

logger = logging.getLogger("whydpi.trace")


def trace_enabled() -> bool:
    """Cheap accessor — returns whether trace was requested at startup."""
    return _TRACE


def trace(fmt: str, *args) -> None:
    """Log *fmt % args* at INFO under the ``whydpi.trace`` logger.

    Guards on :data:`_TRACE` internally so callers may invoke this
    unconditionally, but the fast path is a pure Python bool test —
    no string formatting or attribute lookup on the disabled path.
    """
    if not _TRACE:
        return
    try:
        logger.info(fmt, *args)
    except Exception:  # noqa: BLE001
        # A trace must never crash the shaper or hijacker.  Swallow
        # formatting errors silently — they only matter to a developer
        # who just added a bad format string, and the engine keeps
        # running either way.
        pass


# --------------------------------------------------------------------- helpers
#
# The DNS wire format is stable and tiny; parsing just enough to echo
# QNAME/QTYPE in a trace line avoids pulling in dnspython on the hot
# path.  Anything weird (compressed labels in a question section,
# truncated payload, oversized labels) falls back to "?" so tracing
# never raises.

_DNS_QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 41: "OPT",
    43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3",
    52: "TLSA", 64: "SVCB", 65: "HTTPS", 255: "ANY",
}


def format_dns_question(payload: bytes) -> str:
    """Return ``"example.com A"``-style summary of a DNS wire query.

    The payload is expected to start with a DNS message header (12 B)
    followed by at least one question section.  Returns ``"?"`` on any
    structural error; callers can embed it straight into a trace line.
    """
    try:
        if len(payload) < 13:
            return "?"
        # Question section starts right after the 12-byte header.
        i = 12
        labels: list[str] = []
        # DNS labels are length-prefixed; a zero byte terminates the
        # name.  A compressed pointer (top two bits set) would be weird
        # inside a question but we handle it defensively by bailing.
        while i < len(payload):
            length = payload[i]
            if length == 0:
                i += 1
                break
            if length & 0xC0:
                return "?"
            i += 1
            if i + length > len(payload) or length > 63:
                return "?"
            try:
                labels.append(payload[i:i + length].decode("ascii"))
            except UnicodeDecodeError:
                labels.append(payload[i:i + length].decode("ascii", "replace"))
            i += length
            if len(labels) > 20:
                return "?"
        if i + 4 > len(payload):
            return ".".join(labels) or "."
        qtype_code = int.from_bytes(payload[i:i + 2], "big")
        qtype = _DNS_QTYPE_NAMES.get(qtype_code, str(qtype_code))
        qname = ".".join(labels) or "."
        return f"{qname} {qtype}"
    except Exception:  # noqa: BLE001
        return "?"
