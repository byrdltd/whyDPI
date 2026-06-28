# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

from whydpi.core.failure import FailureKind, classify_reason, dominant_failure


def test_classify_transport() -> None:
    assert classify_reason("connect-failed:111") == FailureKind.TRANSPORT
    assert classify_reason("send-failed:32") == FailureKind.TRANSPORT


def test_classify_dpi() -> None:
    assert classify_reason("non-tls:48545450") == FailureKind.DPI_BLOCK
    assert classify_reason("empty") == FailureKind.DPI_BLOCK


def test_dominant_transport() -> None:
    attempts = [
        ("record:2", "connect-failed:111"),
        ("record:1", "connect-failed:111"),
    ]
    assert dominant_failure(attempts) == FailureKind.TRANSPORT


def test_dominant_success() -> None:
    attempts = [("record:2", "non-tls:abcd"), ("passthrough", "ok")]
    assert dominant_failure(attempts) == FailureKind.SUCCESS
