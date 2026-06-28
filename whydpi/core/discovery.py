# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Adaptive per-connection strategy discovery."""

from __future__ import annotations

import logging
import socket
import sys
import time
from dataclasses import dataclass
from typing import Iterable, Sequence

from ..net.tls_parser import ClientHelloView
from .failure import FailureKind, classify_reason, dominant_failure
from .resolve import AltResolver, UpstreamTarget, client_target, dns_alternate_targets
from .strategy import FragmentPlan, Strategy, build_plan


logger = logging.getLogger(__name__)

_USE_CORK = sys.platform.startswith("linux")
_PASSTHROUGH = Strategy.parse("passthrough")
_DEFAULT_CONNECT_TIMEOUT_S = 1.5

# Failure classes that justify trying a *different* upstream IP for the same
# SNI.  TRANSPORT = the TCP layer never came up.  DPI_BLOCK = the TCP layer
# came up but every shaping strategy (and passthrough) was reset/dropped on
# that address — i.e. the IP or its route is poisoned, not the SNI shaping, so
# a different CDN address (ideally on another anycast range) may slip through.
_ROTATE_FAILURES = (FailureKind.TRANSPORT, FailureKind.DPI_BLOCK)


@dataclass
class DiscoveryResult:
    strategy: Strategy | None
    upstream: socket.socket | None
    server_preview: bytes
    attempts: list[tuple[str, str]]
    target: UpstreamTarget | None = None
    failure_kind: FailureKind = FailureKind.UNKNOWN


def _send_plan(sock: socket.socket, plan: FragmentPlan) -> None:
    cork = getattr(socket, "TCP_CORK", 3)
    for idx, fragment in enumerate(plan.fragments):
        if not fragment:
            continue
        try:
            if _USE_CORK:
                sock.setsockopt(socket.IPPROTO_TCP, cork, 1)
            sock.send(fragment)
            if _USE_CORK:
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
    if len(preview) < min_bytes:
        return False
    return preview[0] == 0x16 and preview[1] == 0x03


def _reached_tls_endpoint(preview: bytes, min_bytes: int) -> bool:
    if len(preview) < min_bytes:
        return False
    return preview[0] in (0x15, 0x16) and preview[1] == 0x03


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


def connect_upstream(
    dest_ip: str,
    dest_port: int,
    mark: int,
    timeout_s: float,
) -> socket.socket:
    family = socket.AF_INET6 if ":" in dest_ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
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


def transport_reachable(
    dest_ip: str,
    dest_port: int,
    proxy_mark: int,
    timeout_s: float,
) -> tuple[bool, str | None]:
    try:
        sock = connect_upstream(dest_ip, dest_port, proxy_mark, timeout_s)
    except OSError as exc:
        return False, f"connect-failed:{exc.errno}"
    try:
        sock.close()
    except OSError:
        pass
    return True, None


def order_candidates(
    cached: Strategy | None,
    default: Strategy,
    fallbacks: Iterable[Strategy],
    *,
    include_passthrough: bool = True,
) -> tuple[Strategy, ...]:
    seen: set[str] = set()
    order: list[Strategy] = []

    def add(strategy: Strategy | None) -> None:
        if strategy is None:
            return
        key = strategy.label()
        if key in seen:
            return
        seen.add(key)
        order.append(strategy)

    add(cached)
    add(default)
    for strategy in platform_fallbacks(fallbacks):
        add(strategy)
    if include_passthrough:
        add(_PASSTHROUGH)
    return tuple(order)


def fragmentation_candidates(
    cached: Strategy | None,
    default: Strategy,
    fallbacks: Iterable[Strategy],
) -> tuple[Strategy, ...]:
    """Strategies that reshape ClientHello — excludes passthrough."""
    return tuple(
        s for s in order_candidates(cached, default, fallbacks, include_passthrough=False)
        if s.layer != "passthrough"
    )


def platform_fallbacks(fallbacks: Iterable[Strategy]) -> tuple[Strategy, ...]:
    if sys.platform.startswith("win"):
        return tuple(fallbacks)
    return tuple(s for s in fallbacks if s.layer != "decoy")


def _probe_one(
    strategy: Strategy,
    *,
    dest_ip: str,
    dest_port: int,
    hello_bytes: bytes,
    hello_view: ClientHelloView,
    proxy_mark: int,
    timeout_s: float,
    success_min_bytes: int,
    accept_alert: bool,
) -> tuple[Strategy, socket.socket | None, bytes, str]:
    plan = build_plan(hello_bytes, hello_view, strategy)
    try:
        upstream = connect_upstream(dest_ip, dest_port, proxy_mark, timeout_s)
    except OSError as exc:
        return strategy, None, b"", f"connect-failed:{exc.errno}"
    try:
        _send_plan(upstream, plan)
    except OSError as exc:
        try:
            upstream.close()
        except OSError:
            pass
        return strategy, None, b"", f"send-failed:{exc.errno}"
    try:
        preview = _peek(upstream, success_min_bytes, timeout_s)
    except (OSError, ConnectionError) as exc:
        try:
            upstream.close()
        except OSError:
            pass
        return strategy, None, b"", f"recv-failed:{type(exc).__name__}"

    accepts = _reached_tls_endpoint if accept_alert else _looks_like_server_hello
    if accepts(preview, success_min_bytes):
        tag = "ok" if preview[:1] == b"\x16" else "ok-alert"
        return strategy, upstream, preview, tag

    reason = "empty" if not preview else (
        f"short:{preview[:2].hex()}" if len(preview) < success_min_bytes
        else f"non-tls:{preview[:4].hex()}"
    )
    try:
        upstream.close()
    except OSError:
        pass
    return strategy, None, preview, reason


def _result_from_probe(
    strategy: Strategy,
    sock: socket.socket | None,
    preview: bytes,
    reason: str,
    target: UpstreamTarget,
    attempts: list[tuple[str, str]],
) -> DiscoveryResult:
    attempts.append((strategy.label(), reason))
    if sock is not None:
        return DiscoveryResult(
            strategy=strategy,
            upstream=sock,
            server_preview=preview,
            attempts=attempts,
            target=target,
            failure_kind=FailureKind.SUCCESS,
        )
    return DiscoveryResult(
        strategy=None,
        upstream=None,
        server_preview=b"",
        attempts=attempts,
        target=target,
        failure_kind=dominant_failure(attempts),
    )


def discover_parallel(
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
    import concurrent.futures as _futures

    attempts: list[tuple[str, str]] = []
    if not candidates:
        return DiscoveryResult(
            strategy=None, upstream=None, server_preview=b"", attempts=attempts,
        )

    winner_strategy: Strategy | None = None
    winner_socket: socket.socket | None = None
    winner_preview: bytes = b""
    max_workers = min(len(candidates), 8)

    with _futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        pending = {
            pool.submit(
                _probe_one,
                strategy,
                dest_ip=dest_ip,
                dest_port=dest_port,
                hello_bytes=hello_bytes,
                hello_view=hello_view,
                proxy_mark=proxy_mark,
                timeout_s=timeout_s,
                success_min_bytes=success_min_bytes,
                accept_alert=accept_alert,
            ): strategy
            for strategy in candidates
        }
        try:
            for fut in _futures.as_completed(pending, timeout=timeout_s + 1.0):
                strategy, sock, preview, reason = fut.result()
                attempts.append((strategy.label(), reason))
                if sock is not None and winner_socket is None:
                    winner_strategy = strategy
                    winner_socket = sock
                    winner_preview = preview
                    for other in pending:
                        other.cancel()
                    break
        except _futures.TimeoutError:
            pass

        for fut in pending:
            if fut.done():
                continue
            fut.cancel()

    kind = dominant_failure(attempts)
    return DiscoveryResult(
        strategy=winner_strategy,
        upstream=winner_socket,
        server_preview=winner_preview,
        attempts=attempts,
        failure_kind=kind,
    )


def _discover_at_target(
    target: UpstreamTarget,
    *,
    hello_bytes: bytes,
    hello_view: ClientHelloView,
    cached: Strategy | None,
    default: Strategy,
    fallbacks: Sequence[Strategy],
    proxy_mark: int,
    connect_timeout_s: float,
    probe_timeout_s: float,
    success_min_bytes: int,
    probe_passthrough_first: bool,
    accept_alert: bool,
) -> DiscoveryResult:
    attempts: list[tuple[str, str]] = []

    reachable, transport_reason = transport_reachable(
        target.ip, target.port, proxy_mark, connect_timeout_s,
    )
    if not reachable:
        label = f"@{target.ip}" if target.source == "dns" else "transport"
        attempts.append((label, transport_reason or "connect-failed:0"))
        return DiscoveryResult(
            strategy=None,
            upstream=None,
            server_preview=b"",
            attempts=attempts,
            target=target,
            failure_kind=FailureKind.TRANSPORT,
        )

    if cached is not None:
        strategy, sock, preview, reason = _probe_one(
            cached,
            dest_ip=target.ip,
            dest_port=target.port,
            hello_bytes=hello_bytes,
            hello_view=hello_view,
            proxy_mark=proxy_mark,
            timeout_s=probe_timeout_s,
            success_min_bytes=success_min_bytes,
            accept_alert=accept_alert,
        )
        if sock is not None:
            return _result_from_probe(cached, sock, preview, reason, target, attempts)
        attempts.append((cached.label(), reason))

    if probe_passthrough_first and cached is None:
        strategy, sock, preview, reason = _probe_one(
            _PASSTHROUGH,
            dest_ip=target.ip,
            dest_port=target.port,
            hello_bytes=hello_bytes,
            hello_view=hello_view,
            proxy_mark=proxy_mark,
            timeout_s=probe_timeout_s,
            success_min_bytes=success_min_bytes,
            accept_alert=accept_alert,
        )
        if sock is not None:
            return _result_from_probe(_PASSTHROUGH, sock, preview, reason, target, attempts)
        attempts.append((_PASSTHROUGH.label(), reason))

    frag = fragmentation_candidates(cached, default, fallbacks)
    if frag:
        raced = discover_parallel(
            dest_ip=target.ip,
            dest_port=target.port,
            hello_bytes=hello_bytes,
            hello_view=hello_view,
            candidates=frag,
            proxy_mark=proxy_mark,
            timeout_s=probe_timeout_s,
            success_min_bytes=success_min_bytes,
            accept_alert=accept_alert,
        )
        attempts.extend(raced.attempts)
        if raced.strategy is not None and raced.upstream is not None:
            return DiscoveryResult(
                strategy=raced.strategy,
                upstream=raced.upstream,
                server_preview=raced.server_preview,
                attempts=attempts,
                target=target,
                failure_kind=FailureKind.SUCCESS,
            )

    if not probe_passthrough_first or cached is not None:
        strategy, sock, preview, reason = _probe_one(
            _PASSTHROUGH,
            dest_ip=target.ip,
            dest_port=target.port,
            hello_bytes=hello_bytes,
            hello_view=hello_view,
            proxy_mark=proxy_mark,
            timeout_s=probe_timeout_s,
            success_min_bytes=success_min_bytes,
            accept_alert=accept_alert,
        )
        if sock is not None:
            return _result_from_probe(_PASSTHROUGH, sock, preview, reason, target, attempts)
        attempts.append((_PASSTHROUGH.label(), reason))

    return DiscoveryResult(
        strategy=None,
        upstream=None,
        server_preview=b"",
        attempts=attempts,
        target=target,
        failure_kind=dominant_failure(attempts),
    )


def discover_upstream(
    *,
    sni: str | None,
    client_dest_ip: str,
    client_dest_port: int,
    hello_bytes: bytes,
    hello_view: ClientHelloView,
    cached: Strategy | None,
    default: Strategy,
    fallbacks: Sequence[Strategy],
    proxy_mark: int,
    timeout_s: float,
    success_min_bytes: int,
    ipv6_enabled: bool = True,
    probe_passthrough_first: bool = True,
    accept_alert: bool = False,
    max_dns_alternates: int = 3,
    connect_timeout_s: float = _DEFAULT_CONNECT_TIMEOUT_S,
    alt_resolver: "AltResolver | None" = None,
) -> DiscoveryResult:
    """Pick a working strategy for one client connection."""
    primary = client_target(client_dest_ip, client_dest_port)
    if primary is None:
        return DiscoveryResult(
            strategy=None,
            upstream=None,
            server_preview=b"",
            attempts=[("client", "resolve-failed")],
            failure_kind=FailureKind.TRANSPORT,
        )

    all_attempts: list[tuple[str, str]] = []
    result = _discover_at_target(
        primary,
        hello_bytes=hello_bytes,
        hello_view=hello_view,
        cached=cached,
        default=default,
        fallbacks=fallbacks,
        proxy_mark=proxy_mark,
        connect_timeout_s=connect_timeout_s,
        probe_timeout_s=timeout_s,
        success_min_bytes=success_min_bytes,
        probe_passthrough_first=probe_passthrough_first,
        accept_alert=accept_alert,
    )
    all_attempts.extend(result.attempts)
    if result.strategy is not None:
        result.attempts = all_attempts
        return result

    if not sni or result.failure_kind not in _ROTATE_FAILURES:
        result.attempts = all_attempts
        return result

    exclude = {primary.ip}
    for alt in dns_alternate_targets(
        sni,
        client_port=client_dest_port,
        exclude_ips=exclude,
        ipv6_enabled=ipv6_enabled,
        max_alternates=max_dns_alternates,
        extra_resolver=alt_resolver,
    ):
        alt_result = _discover_at_target(
            alt,
            hello_bytes=hello_bytes,
            hello_view=hello_view,
            cached=None,
            default=default,
            fallbacks=fallbacks,
            proxy_mark=proxy_mark,
            connect_timeout_s=connect_timeout_s,
            probe_timeout_s=timeout_s,
            success_min_bytes=success_min_bytes,
            probe_passthrough_first=probe_passthrough_first,
            accept_alert=accept_alert,
        )
        all_attempts.extend(alt_result.attempts)
        if alt_result.strategy is not None:
            alt_result.attempts = all_attempts
            return alt_result

    return DiscoveryResult(
        strategy=None,
        upstream=None,
        server_preview=b"",
        attempts=all_attempts,
        failure_kind=dominant_failure(all_attempts),
    )
