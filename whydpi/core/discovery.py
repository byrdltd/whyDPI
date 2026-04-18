# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Adaptive per-connection strategy discovery.

The proxy hands us a client's ClientHello, a destination (ip, port) and a
list of candidate strategies.  We open one upstream socket per candidate
until one produces a byte stream that begins with TLS handshake bytes
(content-type 0x16).  This is specifically chosen to defeat a common DPI
failure mode: returning HTTP-200 block pages (leading byte ``H``) or
injected TCP RST.
"""

from __future__ import annotations

import logging
import socket
import time
from dataclasses import dataclass
from typing import Iterable, Sequence

from ..net.tls_parser import ClientHelloView
from .strategy import FragmentPlan, Strategy, build_plan


logger = logging.getLogger(__name__)


@dataclass
class DiscoveryResult:
    strategy: Strategy | None
    upstream: socket.socket | None
    server_preview: bytes
    attempts: list[tuple[str, str]]  # (label, reason) for each attempt


def _send_plan(sock: socket.socket, plan: FragmentPlan) -> None:
    cork = getattr(socket, "TCP_CORK", 3)
    use_cork = hasattr(socket, "IPPROTO_TCP")
    for idx, fragment in enumerate(plan.fragments):
        if not fragment:
            continue
        try:
            if use_cork:
                sock.setsockopt(socket.IPPROTO_TCP, cork, 1)
            sock.send(fragment)
            if use_cork:
                sock.setsockopt(socket.IPPROTO_TCP, cork, 0)
        except OSError:
            raise
        if idx != len(plan.fragments) - 1 and plan.delay_ms:
            time.sleep(plan.delay_ms / 1000.0)


def _peek(sock: socket.socket, min_bytes: int, timeout_s: float) -> bytes:
    sock.settimeout(timeout_s)
    buf = b""
    deadline = time.monotonic() + timeout_s
    try:
        while len(buf) < min_bytes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                chunk = sock.recv(min_bytes - len(buf))
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
    finally:
        try:
            sock.settimeout(None)
        except OSError:
            pass
    return buf


def _looks_like_server_hello(preview: bytes, min_bytes: int) -> bool:
    """Strict: server sent a TLS handshake record (0x16)."""
    if len(preview) < min_bytes:
        return False
    return preview[0] == 0x16 and preview[1] == 0x03


def _reached_tls_endpoint(preview: bytes, min_bytes: int) -> bool:
    """Loose: server replied with any valid TLS record (handshake or alert).

    An ``alert`` (0x15) means the peer is a real TLS server but didn't like
    the ClientHello — this is common with synthetic probes that don't carry
    a complete TLS 1.3 key exchange.  Injected block pages start with ASCII
    (``H``, ``<``) and do not look like this.
    """
    if len(preview) < min_bytes:
        return False
    return preview[0] in (0x15, 0x16) and preview[1] == 0x03


def _connect(dest_ip: str, dest_port: int, mark: int, timeout_s: float) -> socket.socket:
    family = socket.AF_INET6 if ":" in dest_ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    # SO_MARK prevents iptables loop on the proxy's upstream socket.  It
    # requires CAP_NET_ADMIN, so we only apply it when we have the privilege
    # — probes and self-tests run unprivileged.
    if mark and _has_net_admin():
        try:
            sock.setsockopt(socket.SOL_SOCKET, _so_mark(), mark)
        except OSError:
            pass
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(timeout_s)
    try:
        if family == socket.AF_INET6:
            sock.connect((dest_ip, dest_port, 0, 0))
        else:
            sock.connect((dest_ip, dest_port))
    except OSError:
        sock.close()
        raise
    sock.settimeout(None)
    return sock


_NET_ADMIN_CACHE: bool | None = None


def _has_net_admin() -> bool:
    global _NET_ADMIN_CACHE
    if _NET_ADMIN_CACHE is not None:
        return _NET_ADMIN_CACHE
    try:
        import os
        _NET_ADMIN_CACHE = hasattr(os, "geteuid") and os.geteuid() == 0
    except Exception:
        _NET_ADMIN_CACHE = False
    return _NET_ADMIN_CACHE


def _so_mark() -> int:
    return getattr(socket, "SO_MARK", 36)


def discover(
    *,
    dest_ip: str,
    dest_port: int,
    hello_bytes: bytes,
    hello_view: ClientHelloView,
    candidates: Sequence[Strategy],
    proxy_mark: int,
    timeout_s: float,
    success_min_bytes: int,
    accept_alert: bool = False,
) -> DiscoveryResult:
    attempts: list[tuple[str, str]] = []
    accepts = _reached_tls_endpoint if accept_alert else _looks_like_server_hello

    for strategy in candidates:
        plan = build_plan(hello_bytes, hello_view, strategy)
        try:
            upstream = _connect(dest_ip, dest_port, proxy_mark, timeout_s)
        except OSError as exc:
            attempts.append((strategy.label(), f"connect-failed:{exc.errno}"))
            continue

        try:
            _send_plan(upstream, plan)
        except OSError as exc:
            attempts.append((strategy.label(), f"send-failed:{exc.errno}"))
            upstream.close()
            continue

        preview = _peek(upstream, success_min_bytes, timeout_s)
        if accepts(preview, success_min_bytes):
            tag = "ok" if preview[:1] == b"\x16" else "ok-alert"
            attempts.append((strategy.label(), tag))
            return DiscoveryResult(
                strategy=strategy,
                upstream=upstream,
                server_preview=preview,
                attempts=attempts,
            )

        reason = "empty" if not preview else (
            f"short:{preview[:2].hex()}" if len(preview) < success_min_bytes
            else f"non-tls:{preview[:4].hex()}"
        )
        attempts.append((strategy.label(), reason))
        try:
            upstream.close()
        except OSError:
            pass

    return DiscoveryResult(
        strategy=None,
        upstream=None,
        server_preview=b"",
        attempts=attempts,
    )


def order_candidates(
    cached: Strategy | None,
    default: Strategy,
    fallbacks: Iterable[Strategy],
) -> tuple[Strategy, ...]:
    """Build the ordered attempt list: cached first, then default, then fallbacks.

    Duplicates are removed while preserving order.
    """
    seen: set[str] = set()
    order: list[Strategy] = []
    for s in (cached, default, *fallbacks):
        if s is None:
            continue
        key = s.label()
        if key in seen:
            continue
        seen.add(key)
        order.append(s)
    return tuple(order)
