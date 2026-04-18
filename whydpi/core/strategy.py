# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Composable TLS fragmentation strategies.

A strategy is a tuple of (layer, offset, chunk_size).  The previous six named
modes (``record``, ``header``, ``sni``, ``half``, ``random``, ``chunked``)
collapse into specific values of these three axes:

* layer    — ``record`` (re-frame as two TLS records) or ``tcp``
  (single TLS record split across two TCP sends).
* offset   — integer, ``sni-mid``, ``half``, ``random`` or ``chunked``.
* chunk_sz — only for chunked; chunk size in bytes.

Grammar (used by :func:`Strategy.parse`):

    record:2          record split at payload[2]
    record:sni-mid    record split at (sni_offset + sni_length/2)
    record:half       record split at payload midpoint
    tcp:sni-mid       TCP-level split at sni midpoint, single TLS record
    chunked:40        TCP-level split every 40 bytes
    passthrough       no transformation; send as-is
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field
from typing import Iterable, Literal

from ..net.tls_parser import ClientHelloView


Layer = Literal["record", "tcp", "passthrough"]
OffsetKind = Literal["fixed", "sni-mid", "half", "random", "chunked"]


@dataclass(frozen=True)
class Strategy:
    layer: Layer
    offset_kind: OffsetKind
    offset_value: int = 0        # fixed offset or chunk size
    delay_ms: tuple[int, int] = (0, 0)

    def label(self) -> str:
        if self.layer == "passthrough":
            return "passthrough"
        if self.offset_kind == "chunked":
            return f"chunked:{self.offset_value}"
        if self.offset_kind == "fixed":
            return f"{self.layer}:{self.offset_value}"
        return f"{self.layer}:{self.offset_kind}"

    @classmethod
    def parse(cls, spec: str) -> "Strategy":
        spec = spec.strip().lower()
        if spec in ("passthrough", "none", "off"):
            return cls(layer="passthrough", offset_kind="fixed", offset_value=0)
        if ":" not in spec:
            raise ValueError(f"invalid strategy spec: {spec!r}")

        left, right = spec.split(":", 1)
        if left == "chunked":
            size = int(right)
            if size < 1:
                raise ValueError("chunked size must be >= 1")
            return cls(layer="tcp", offset_kind="chunked", offset_value=size)

        if left not in ("record", "tcp"):
            raise ValueError(f"unknown strategy layer: {left!r}")

        if right in ("sni-mid", "half", "random"):
            return cls(layer=left, offset_kind=right, offset_value=0)  # type: ignore[arg-type]
        try:
            return cls(layer=left, offset_kind="fixed", offset_value=int(right))  # type: ignore[arg-type]
        except ValueError as exc:
            raise ValueError(f"invalid strategy spec: {spec!r}") from exc


@dataclass(frozen=True)
class FragmentPlan:
    strategy: Strategy
    fragments: tuple[bytes, ...] = field(default_factory=tuple)
    delay_ms: int = 0

    @property
    def label(self) -> str:
        return self.strategy.label()


# ---------------------------------------------------------------------------
# Offset resolution
# ---------------------------------------------------------------------------

def _resolve_offset(payload_len: int, strategy: Strategy, hello: ClientHelloView) -> int:
    if payload_len < 2:
        return payload_len

    kind = strategy.offset_kind
    if kind == "fixed":
        return max(1, min(strategy.offset_value, payload_len - 1))
    if kind == "half":
        return max(1, payload_len // 2)
    if kind == "random":
        return random.randint(2, max(2, payload_len - 2))
    if kind == "sni-mid":
        if hello.sni_offset is not None and hello.sni_length:
            # `hello.sni_offset` is relative to the outer record (includes the
            # 5-byte header).  Translate to payload-relative offset.
            raw_mid = hello.sni_offset + max(1, hello.sni_length // 2)
            payload_mid = raw_mid - 5
            return max(1, min(payload_mid, payload_len - 1))
        return max(1, payload_len // 2)
    return max(1, min(strategy.offset_value or 2, payload_len - 1))


# ---------------------------------------------------------------------------
# Layer transforms
# ---------------------------------------------------------------------------

def _record_split(data: bytes, offset: int) -> tuple[bytes, ...]:
    """Re-frame a single TLS record as two valid TLS records at *offset*."""
    if len(data) < 6:
        return (data,)
    ct = data[0:1]
    ver = data[1:3]
    payload = data[5:]
    pos = max(1, min(offset, len(payload) - 1))
    rec1 = ct + ver + struct.pack("!H", pos) + payload[:pos]
    rec2 = ct + ver + struct.pack("!H", len(payload) - pos) + payload[pos:]
    return (rec1, rec2)


def _tcp_split(data: bytes, offset: int) -> tuple[bytes, ...]:
    """Split the raw record bytes across two TCP sends (no re-framing)."""
    pos = max(1, min(offset, len(data) - 1))
    return (data[:pos], data[pos:])


def _chunked(data: bytes, size: int) -> tuple[bytes, ...]:
    if size < 1:
        return (data,)
    return tuple(data[i:i + size] for i in range(0, len(data), size)) or (data,)


# ---------------------------------------------------------------------------
# Plan builder
# ---------------------------------------------------------------------------

def build_plan(data: bytes, hello: ClientHelloView, strategy: Strategy) -> FragmentPlan:
    if strategy.layer == "passthrough":
        return FragmentPlan(strategy=strategy, fragments=(data,), delay_ms=0)

    payload_len = max(0, len(data) - 5)
    if strategy.offset_kind == "chunked":
        return FragmentPlan(
            strategy=strategy,
            fragments=_chunked(data, strategy.offset_value or 40),
            delay_ms=0,
        )

    offset = _resolve_offset(payload_len, strategy, hello)
    if strategy.layer == "record":
        return FragmentPlan(
            strategy=strategy,
            fragments=_record_split(data, offset),
            delay_ms=_delay(strategy.delay_ms),
        )
    # tcp split uses data-relative offset (header + payload).
    tcp_offset = offset + 5 if strategy.offset_kind != "fixed" else offset
    return FragmentPlan(
        strategy=strategy,
        fragments=_tcp_split(data, tcp_offset),
        delay_ms=_delay(strategy.delay_ms),
    )


def _delay(range_ms: tuple[int, int]) -> int:
    low, high = sorted((max(0, range_ms[0]), max(0, range_ms[1])))
    if high == 0:
        return 0
    return random.randint(low or 1, high)


def parse_fallback(specs: Iterable[str]) -> tuple[Strategy, ...]:
    return tuple(Strategy.parse(spec) for spec in specs)
