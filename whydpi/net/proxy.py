# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Dual-stack transparent TLS proxy with adaptive per-SNI strategy discovery.

Connections arrive here via netfilter REDIRECT.  For each connection:

1. ``SO_ORIGINAL_DST`` (v4) or ``IP6T_SO_ORIGINAL_DST`` (v6) recovers the
   intended destination.
2. We read the full ClientHello from the client.
3. If the SNI is known and marked passthrough, we forward unchanged.
4. Otherwise we consult the strategy cache and try strategies in order,
   stopping on the first one whose upstream reply begins with a valid TLS
   record (content-type ``0x16``).  The winner is cached per-SNI.
5. Bidirectional relay until either side closes.

Nothing in this module contains or depends on any hostname — the SNI comes
from the client's own ClientHello at runtime.
"""

from __future__ import annotations

import logging
import select
import socket
import struct
import threading
from dataclasses import dataclass
from typing import Iterable

from ..core.cache import StrategyCache
from ..core.discovery import discover, order_candidates
from ..core.strategy import FragmentPlan, Strategy, build_plan
from .tls_parser import ClientHelloView, looks_like_client_hello, parse_client_hello, read_client_hello


logger = logging.getLogger(__name__)


# Linux option constants (platform-specific, not exposed in python stdlib).
_SO_ORIGINAL_DST = 80   # same numeric value for v4 and v6


def _get_original_dst_v4(sock: socket.socket) -> tuple[str, int]:
    raw = sock.getsockopt(socket.SOL_IP, _SO_ORIGINAL_DST, 16)
    port = struct.unpack_from("!H", raw, 2)[0]
    ip = socket.inet_ntoa(raw[4:8])
    return ip, port


def _get_original_dst_v6(sock: socket.socket) -> tuple[str, int]:
    raw = sock.getsockopt(socket.IPPROTO_IPV6, _SO_ORIGINAL_DST, 28)
    port = struct.unpack_from("!H", raw, 2)[0]
    ip = socket.inet_ntop(socket.AF_INET6, raw[8:24])
    return ip, port


def _matches_suffix(host: str, suffixes: Iterable[str]) -> bool:
    if not host:
        return False
    h = host.lower().strip(".")
    for suf in suffixes:
        suf = suf.lower().lstrip(".")
        if suf and (h == suf or h.endswith("." + suf)):
            return True
    return False


def _relay(a: socket.socket, b: socket.socket, initial_b_to_a: bytes = b"") -> None:
    """Bidirectional relay; optionally prime the a-side with bytes we already
    received from b during discovery (so we don't lose the peeked ServerHello).
    """
    try:
        if initial_b_to_a:
            a.sendall(initial_b_to_a)
    except OSError:
        return

    pair = [a, b]
    try:
        while True:
            readable, _, exceptional = select.select(pair, [], pair, 60)
            if exceptional or not readable:
                break
            for s in readable:
                try:
                    data = s.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                try:
                    (b if s is a else a).sendall(data)
                except OSError:
                    return
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------

@dataclass
class ProxyContext:
    default_strategy: Strategy
    fallbacks: tuple[Strategy, ...]
    proxy_mark: int
    timeout_s: float
    success_min_bytes: int
    passthrough_sni: tuple[str, ...]
    cache: StrategyCache


def _handle(client: socket.socket, family: int, ctx: ProxyContext) -> None:
    upstream: socket.socket | None = None
    try:
        if family == socket.AF_INET6:
            dest_ip, dest_port = _get_original_dst_v6(client)
        else:
            dest_ip, dest_port = _get_original_dst_v4(client)

        hello_bytes = read_client_hello(client, timeout_s=5.0)
        if not hello_bytes:
            return

        if not looks_like_client_hello(hello_bytes):
            upstream = _connect_plain(dest_ip, dest_port, ctx.proxy_mark, ctx.timeout_s)
            if upstream is None:
                return
            upstream.sendall(hello_bytes)
            _relay(client, upstream)
            return

        view = parse_client_hello(hello_bytes)
        sni = (view.sni or "").lower()

        if sni and _matches_suffix(sni, ctx.passthrough_sni):
            upstream = _connect_plain(dest_ip, dest_port, ctx.proxy_mark, ctx.timeout_s)
            if upstream is None:
                return
            upstream.sendall(hello_bytes)
            logger.debug("passthrough sni=%s bytes=%d", sni or "?", len(hello_bytes))
            _relay(client, upstream)
            return

        cached = None
        entry = ctx.cache.get(sni) if sni else None
        if entry is not None:
            try:
                cached = Strategy.parse(entry.strategy)
            except ValueError:
                cached = None

        candidates = order_candidates(cached, ctx.default_strategy, ctx.fallbacks)
        result = discover(
            dest_ip=dest_ip,
            dest_port=dest_port,
            hello_bytes=hello_bytes,
            hello_view=view,
            candidates=candidates,
            proxy_mark=ctx.proxy_mark,
            timeout_s=ctx.timeout_s,
            success_min_bytes=ctx.success_min_bytes,
        )

        if result.strategy is None or result.upstream is None:
            logger.warning(
                "no working strategy sni=%s attempts=%s",
                sni or "?",
                ",".join(f"{lbl}:{reason}" for lbl, reason in result.attempts),
            )
            return

        upstream = result.upstream
        if sni:
            if cached and cached.label() != result.strategy.label():
                ctx.cache.record_failure(sni, cached.label())
            ctx.cache.record_success(sni, result.strategy.label())

        logger.debug(
            "sni=%s strategy=%s attempts=%s",
            sni or "?",
            result.strategy.label(),
            ",".join(f"{lbl}:{reason}" for lbl, reason in result.attempts),
        )
        _relay(client, upstream, initial_b_to_a=result.server_preview)

    except OSError as exc:
        logger.debug("proxy handler OSError: %s", exc)
    finally:
        for s in (client, upstream):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass


def _connect_plain(dest_ip: str, dest_port: int, mark: int, timeout: float) -> socket.socket | None:
    family = socket.AF_INET6 if ":" in dest_ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), mark)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(timeout)
    try:
        if family == socket.AF_INET6:
            sock.connect((dest_ip, dest_port, 0, 0))
        else:
            sock.connect((dest_ip, dest_port))
        sock.settimeout(None)
        return sock
    except OSError:
        sock.close()
        return None


# ---------------------------------------------------------------------------
# Listener
# ---------------------------------------------------------------------------

class TransparentTLSProxy:
    def __init__(
        self,
        *,
        port: int,
        proxy_mark: int,
        default_strategy: Strategy,
        fallbacks: Iterable[Strategy],
        cache: StrategyCache,
        timeout_s: float,
        success_min_bytes: int,
        passthrough_sni: Iterable[str],
        ipv6_enabled: bool,
    ):
        self._port = port
        self._ctx = ProxyContext(
            default_strategy=default_strategy,
            fallbacks=tuple(fallbacks),
            proxy_mark=proxy_mark,
            timeout_s=timeout_s,
            success_min_bytes=success_min_bytes,
            passthrough_sni=tuple(passthrough_sni),
            cache=cache,
        )
        self._ipv6 = ipv6_enabled
        self._sockets: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self._running = False

    def start(self) -> None:
        self._running = True
        v4 = self._listen(socket.AF_INET, "127.0.0.1")
        if v4 is not None:
            self._sockets.append(v4)
            self._threads.append(self._spawn(v4, socket.AF_INET, "tls-proxy-v4"))

        if self._ipv6:
            v6 = self._listen(socket.AF_INET6, "::1")
            if v6 is not None:
                self._sockets.append(v6)
                self._threads.append(self._spawn(v6, socket.AF_INET6, "tls-proxy-v6"))

        logger.info(
            "transparent TLS proxy listening on :%s (%s) default=%s",
            self._port,
            "v4+v6" if self._ipv6 else "v4",
            self._ctx.default_strategy.label(),
        )

    def _listen(self, family: int, addr: str) -> socket.socket | None:
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((addr, self._port, 0, 0))
            else:
                sock.bind((addr, self._port))
            sock.listen(512)
            return sock
        except OSError as exc:
            logger.warning("listen %s failed: %s", addr, exc)
            return None

    def _spawn(self, sock: socket.socket, family: int, name: str) -> threading.Thread:
        t = threading.Thread(target=self._serve, args=(sock, family), name=name, daemon=True)
        t.start()
        return t

    def _serve(self, sock: socket.socket, family: int) -> None:
        while self._running:
            try:
                sock.settimeout(1.0)
                client, _addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=_handle, args=(client, family, self._ctx), daemon=True
            ).start()

    def stop(self) -> None:
        self._running = False
        for s in self._sockets:
            try:
                s.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=2)
        logger.info("transparent TLS proxy stopped")
