# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Classify per-attempt and per-probe failure modes.

DPI middleboxes, transport blocks, and sites that need no shaping produce
different reason strings during discovery.  The proxy uses these classes to
decide whether to try another IP, skip pointless strategy churn, or cache
passthrough.
"""

from __future__ import annotations

from enum import Enum


class FailureKind(str, Enum):
    SUCCESS = "success"
    TRANSPORT = "transport"
    DPI_BLOCK = "dpi_block"
    RECV_ERROR = "recv_error"
    UNKNOWN = "unknown"


def classify_reason(reason: str) -> FailureKind:
    if reason in ("ok", "ok-alert"):
        return FailureKind.SUCCESS
    if reason.startswith(("connect-failed:", "send-failed:")):
        return FailureKind.TRANSPORT
    if reason.startswith(("empty", "short:", "non-tls:")):
        return FailureKind.DPI_BLOCK
    if reason.startswith(("recv-failed:", "late:")):
        return FailureKind.RECV_ERROR
    return FailureKind.UNKNOWN


def dominant_failure(attempts: list[tuple[str, str]]) -> FailureKind:
    """Pick the most informative failure class for a finished probe."""
    if any(classify_reason(r) == FailureKind.SUCCESS for _, r in attempts):
        return FailureKind.SUCCESS
    kinds = [classify_reason(r) for _, r in attempts]
    if all(k == FailureKind.TRANSPORT for k in kinds) and kinds:
        return FailureKind.TRANSPORT
    if FailureKind.DPI_BLOCK in kinds:
        return FailureKind.DPI_BLOCK
    if FailureKind.RECV_ERROR in kinds:
        return FailureKind.RECV_ERROR
    if FailureKind.TRANSPORT in kinds:
        return FailureKind.TRANSPORT
    return FailureKind.UNKNOWN


def format_summary(kind: FailureKind, attempts: list[tuple[str, str]]) -> str:
    detail = ",".join(f"{lbl}:{reason}" for lbl, reason in attempts)
    if kind == FailureKind.TRANSPORT:
        return f"transport block (upstream TCP unreachable) — {detail}"
    if kind == FailureKind.DPI_BLOCK:
        return f"DPI or TLS rejection — {detail}"
    if kind == FailureKind.SUCCESS:
        return detail
    return detail
