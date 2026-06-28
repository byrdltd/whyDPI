# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Dual-stack transparent TLS proxy with adaptive per-SNI strategy discovery."""

from __future__ import annotations

import itertools
import logging
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Iterable

from ..core.cache import StrategyCache
from ..core.discovery import connect_upstream, discover_upstream
from ..core.failure import format_summary
from ..core.resolve import AltResolver
from ..core.strategy import Strategy
from ..settings import passthrough_contains
from .tls_parser import looks_like_client_hello, parse_client_hello, read_client_hello


logger = logging.getLogger(__name__)

_SO_ORIGINAL_DST = 80

# Per-connection id so a single browser's many parallel streams can be told
# apart in the log when diagnosing a failure.
_conn_seq = itertools.count(1)


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


def _relay(
    a: socket.socket, b: socket.socket, initial_b_to_a: bytes = b"",
) -> tuple[int, int, str]:
    """Pump bytes between *a* (client) and *b* (upstream).

    Returns ``(client_to_upstream, upstream_to_client, reason)`` where
    ``reason`` names whichever side ended the relay first.  The byte counts
    and reason are purely diagnostic but make it possible to tell "the origin
    sent a ServerHello then immediately reset" apart from "the client never
    sent anything" — the kind of distinction that separates a working proxy
    path from a browser-side abort.
    """
    a_to_b = 0
    b_to_a = len(initial_b_to_a)
    try:
        if initial_b_to_a:
            a.sendall(initial_b_to_a)
    except OSError as exc:
        return a_to_b, b_to_a, f"initial-send-error:{exc.errno}"

    pair = [a, b]
    try:
        while True:
            readable, _, exceptional = select.select(pair, [], pair, 60)
            if exceptional:
                return a_to_b, b_to_a, "exceptional"
            if not readable:
                return a_to_b, b_to_a, "idle-timeout-60s"
            for s in readable:
                try:
                    data = s.recv(65536)
                except OSError as exc:
                    side = "client" if s is a else "upstream"
                    return a_to_b, b_to_a, f"{side}-recv-error:{exc.errno}"
                if not data:
                    side = "client" if s is a else "upstream"
                    return a_to_b, b_to_a, f"{side}-eof"
                try:
                    (b if s is a else a).sendall(data)
                except OSError as exc:
                    side = "upstream" if s is a else "client"
                    return a_to_b, b_to_a, f"{side}-send-error:{exc.errno}"
                if s is a:
                    a_to_b += len(data)
                else:
                    b_to_a += len(data)
    except OSError as exc:
        return a_to_b, b_to_a, f"select-error:{exc.errno}"


@dataclass
class ProxyContext:
    default_strategy: Strategy
    fallbacks: tuple[Strategy, ...]
    proxy_mark: int
    timeout_s: float
    success_min_bytes: int
    passthrough_sni: tuple[str, ...]
    probe_passthrough_first: bool
    ipv6_enabled: bool
    cache: StrategyCache
    alt_resolver: "AltResolver | None" = None


def _relay_passthrough(
    client: socket.socket,
    dest_ip: str,
    dest_port: int,
    hello_bytes: bytes,
    ctx: ProxyContext,
    *,
    sni: str,
    cid: int,
    path: str,
) -> socket.socket | None:
    try:
        upstream = connect_upstream(dest_ip, dest_port, ctx.proxy_mark, ctx.timeout_s)
    except OSError as exc:
        logger.debug(
            "conn#%d %s sni=%s dest=%s connect-failed errno=%s",
            cid, path, sni or "?", dest_ip, exc.errno,
        )
        return None
    upstream.sendall(hello_bytes)
    a2b, b2a, reason = _relay(client, upstream)
    logger.debug(
        "conn#%d %s sni=%s dest=%s hello=%dB relay c->u=%dB u->c=%dB end=%s",
        cid, path, sni or "?", dest_ip, len(hello_bytes), a2b, b2a, reason,
    )
    return upstream


def _handle(client: socket.socket, family: int, ctx: ProxyContext) -> None:
    upstream: socket.socket | None = None
    cid = next(_conn_seq)
    fam = "v6" if family == socket.AF_INET6 else "v4"
    t0 = time.monotonic()
    try:
        if family == socket.AF_INET6:
            dest_ip, dest_port = _get_original_dst_v6(client)
        else:
            dest_ip, dest_port = _get_original_dst_v4(client)

        hello_bytes = read_client_hello(client, timeout_s=5.0)
        if not hello_bytes:
            logger.debug(
                "conn#%d %s dest=[%s]:%d closed before sending any ClientHello",
                cid, fam, dest_ip, dest_port,
            )
            return

        if not looks_like_client_hello(hello_bytes):
            logger.debug(
                "conn#%d %s dest=[%s]:%d non-TLS first=%#04x bytes=%d -> blind relay",
                cid, fam, dest_ip, dest_port,
                hello_bytes[0] if hello_bytes else 0, len(hello_bytes),
            )
            try:
                upstream = connect_upstream(dest_ip, dest_port, ctx.proxy_mark, ctx.timeout_s)
            except OSError as exc:
                logger.debug("conn#%d blind-relay connect-failed errno=%s", cid, exc.errno)
                return
            upstream.sendall(hello_bytes)
            _relay(client, upstream)
            return

        view = parse_client_hello(hello_bytes)
        sni = (view.sni or "").lower()
        logger.debug(
            "conn#%d %s dest=[%s]:%d sni=%s hello=%dB",
            cid, fam, dest_ip, dest_port, sni or "(none)", len(hello_bytes),
        )

        if sni and passthrough_contains(ctx.passthrough_sni, sni):
            upstream = _relay_passthrough(
                client, dest_ip, dest_port, hello_bytes, ctx,
                sni=sni, cid=cid, path="user-passthrough",
            )
            if upstream is not None:
                return
            # The client-chosen address is unreachable.  Even an explicit
            # passthrough cannot connect there, so fall through to discovery,
            # which probes passthrough first and then rotates onto a working
            # address — honouring the no-fragmentation intent when it can.
            upstream = None

        cached = None
        entry = ctx.cache.get(sni) if sni else None
        if entry is not None:
            try:
                cached = Strategy.parse(entry.strategy)
            except ValueError:
                cached = None

        if cached is not None and cached.layer == "passthrough":
            upstream = _relay_passthrough(
                client, dest_ip, dest_port, hello_bytes, ctx,
                sni=sni, cid=cid, path="cached-passthrough",
            )
            if upstream is not None:
                return
            # A cached 'passthrough' verdict only records *that* passthrough
            # worked, not the address it worked on — discovery may have won on
            # a rotated IP we no longer remember.  When the client's own choice
            # is range-blocked (connect refused/timeout) the shortcut is a dead
            # end, so fall through to full discovery instead of giving up.
            logger.debug(
                "conn#%d cached-passthrough unreachable; falling through to discovery",
                cid,
            )
            upstream = None

        result = discover_upstream(
            sni=sni or None,
            client_dest_ip=dest_ip,
            client_dest_port=dest_port,
            hello_bytes=hello_bytes,
            hello_view=view,
            cached=cached,
            default=ctx.default_strategy,
            fallbacks=ctx.fallbacks,
            proxy_mark=ctx.proxy_mark,
            timeout_s=ctx.timeout_s,
            success_min_bytes=ctx.success_min_bytes,
            ipv6_enabled=ctx.ipv6_enabled,
            probe_passthrough_first=ctx.probe_passthrough_first,
            alt_resolver=ctx.alt_resolver,
        )

        attempts_str = ",".join(f"{lbl}:{reason}" for lbl, reason in result.attempts)
        if result.strategy is None or result.upstream is None:
            summary = format_summary(result.failure_kind, result.attempts)
            logger.warning(
                "conn#%d %s sni=%s NO-STRATEGY kind=%s attempts=[%s] %s",
                cid, fam, sni or "?", result.failure_kind.value, attempts_str, summary,
            )
            if sni:
                ctx.cache.record_failure_kind(sni, result.failure_kind.value)
            return

        upstream = result.upstream
        if sni:
            if cached and cached.label() != result.strategy.label():
                ctx.cache.record_failure(sni, cached.label())
            ctx.cache.record_success(sni, result.strategy.label())

        tgt = (
            f"{result.target.ip}({result.target.source})"
            if result.target is not None else f"{dest_ip}(orig)"
        )
        a2b, b2a, reason = _relay(client, upstream, initial_b_to_a=result.server_preview)
        logger.debug(
            "conn#%d %s sni=%s strategy=%s via %s preview=%dB attempts=[%s] "
            "relay c->u=%dB u->c=%dB end=%s dur=%.1fs",
            cid, fam, sni or "?", result.strategy.label(), tgt,
            len(result.server_preview or b""), attempts_str,
            a2b, b2a, reason, time.monotonic() - t0,
        )

    except OSError as exc:
        logger.debug("conn#%d %s handler OSError: %s", cid, fam, exc)
    finally:
        for s in (client, upstream):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass


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
        probe_passthrough_first: bool,
        ipv6_enabled: bool,
        alt_resolver: "AltResolver | None" = None,
    ):
        self._port = port
        self._ctx = ProxyContext(
            default_strategy=default_strategy,
            fallbacks=tuple(fallbacks),
            proxy_mark=proxy_mark,
            timeout_s=timeout_s,
            success_min_bytes=success_min_bytes,
            passthrough_sni=tuple(passthrough_sni),
            probe_passthrough_first=probe_passthrough_first,
            ipv6_enabled=ipv6_enabled,
            cache=cache,
            alt_resolver=alt_resolver,
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
            "transparent TLS proxy listening on :%s (%s) default=%s passthrough_probe=%s",
            self._port,
            "v4+v6" if self._ipv6 else "v4",
            self._ctx.default_strategy.label(),
            self._ctx.probe_passthrough_first,
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
