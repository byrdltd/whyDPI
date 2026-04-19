# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""DoH client, connection pool, and local DNS stub server.

Design notes
============
This module is the resolver side of whyDPI: every DNS query we serve
(directly via the Linux stub, or via the Windows packet-layer
hijacker) is forwarded as a wire-format DNS-over-HTTPS POST to a
public resolver.  Because the DoH request is a regular outbound HTTPS
connection, it is transparently intercepted by our TLS proxy and gets
the same record-split treatment as ordinary web traffic — no domain
name ever leaves the host in the clear.

Historically :class:`DoHClient` opened a fresh TCP+TLS connection per
query and sent ``Connection: close``.  On a page load that resolves
40+ distinct hostnames this multiplies into 40 TLS handshakes, each
costing 50-200 ms round-trip, and the hijacker looks like a DoS
attack on its own upstream.  :class:`DoHConnectionPool` fixes this by
running HTTP/1.1 keep-alive: a small pool (default 8) of long-lived
TLS sockets serve queries back-to-back, and only break-and-reopen on
a genuine wire failure.  Against ``cloudflare-dns.com`` this reduces
per-query cost from one TLS handshake down to one request/response
on an existing stream — typically <5 ms RTT.

All state is RAM-only.  Pool connections close on :meth:`DoHClient.close`,
which is called from the engine's shutdown path alongside the strategy
cache wipe so nothing outlives the tray session.
"""

from __future__ import annotations

import logging
import queue
import socket
import ssl
import struct
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from .dns_cache import DnsCache


logger = logging.getLogger(__name__)

DOH_CONTENT_TYPE = "application/dns-message"


@dataclass(frozen=True)
class DoHEndpoint:
    ip: str
    path: str = "/dns-query"
    port: int = 443
    # Hostname to present in SNI *and* verify the server certificate
    # against.  Without this the DoH socket reaches the resolver by IP
    # alone and has no cryptographic identity to check — a transparent
    # MITM on UDP-53 (the exact threat model we are trying to defeat)
    # can trivially substitute its own DoH response and pin our whole
    # tool to the attacker's block-page IPs.  Each known public
    # resolver ships with its certificate hostname baked into the
    # defaults table in :mod:`whydpi.settings`.
    hostname: str | None = None


# ---------------------------------------------------------------------------
# Keep-alive connection + pool
# ---------------------------------------------------------------------------

class _DoHConnection:
    """Single persistent HTTP/1.1 keep-alive DoH connection.

    The connection owns one TCP socket and its TLS overlay.  Leftover
    response bytes between requests are buffered here so pipelined
    replies don't get re-read from the kernel for every new query.
    """

    __slots__ = ("_sock", "_tls", "_buf", "_endpoint", "_timeout", "_closed")

    def __init__(
        self,
        endpoint: DoHEndpoint,
        timeout_s: float,
        ctx: ssl.SSLContext,
    ) -> None:
        family = socket.AF_INET6 if ":" in endpoint.ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout_s)
        try:
            # DoH queries are small (≤ 512 B) and latency-sensitive;
            # Nagle would only ever hurt us here.
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        if family == socket.AF_INET6:
            sock.connect((endpoint.ip, endpoint.port, 0, 0))
        else:
            sock.connect((endpoint.ip, endpoint.port))
        self._sock = sock
        # ``endpoint.hostname`` drives both the TLS SNI we put on the
        # wire and the name we match against the peer's certificate.
        # The caller supplies an ``ssl.SSLContext`` with
        # ``verify_mode=CERT_REQUIRED`` and ``check_hostname=True`` so
        # any MITM on UDP-53 (or, more importantly, on our DoH socket
        # itself) fails the handshake instead of silently feeding us
        # the attacker's DNS answers.
        server_hostname = endpoint.hostname or None
        self._tls = ctx.wrap_socket(sock, server_hostname=server_hostname)
        self._buf = bytearray()
        self._endpoint = endpoint
        self._timeout = timeout_s
        self._closed = False

    def is_open(self) -> bool:
        return not self._closed

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._tls.close()
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass

    def query(self, wire: bytes) -> bytes:
        """Send one DoH request and read back exactly one response.

        Raises ``OSError`` on any wire-level failure so the pool can
        discard this connection and open a fresh one.
        """
        self._tls.settimeout(self._timeout)
        request = (
            f"POST {self._endpoint.path} HTTP/1.1\r\n"
            f"Host: {self._endpoint.ip}\r\n"
            f"Content-Type: {DOH_CONTENT_TYPE}\r\n"
            f"Accept: {DOH_CONTENT_TYPE}\r\n"
            f"Content-Length: {len(wire)}\r\n"
            f"Connection: keep-alive\r\n\r\n"
        ).encode("ascii") + wire
        self._tls.sendall(request)
        return self._read_one_response()

    # -- Response parsing ------------------------------------------------

    def _read_one_response(self) -> bytes:
        headers_text, remainder = self._drain_to_header()
        content_length = 0
        chunked = False
        close_after = False
        for line in headers_text.split("\r\n")[1:]:
            lower = line.lower()
            if lower.startswith("content-length:"):
                try:
                    content_length = int(lower.split(":", 1)[1].strip())
                except ValueError:
                    content_length = 0
            elif lower.startswith("transfer-encoding:") and "chunked" in lower:
                chunked = True
            elif lower.startswith("connection:") and "close" in lower:
                close_after = True

        if chunked:
            body, consumed = self._read_chunked(remainder)
            self._buf = bytearray(remainder[consumed:])
        else:
            # Content-Length path (DoH servers always send it).
            body = bytearray(remainder[:content_length])
            need = content_length - len(body)
            while need > 0:
                chunk = self._tls.recv(min(65536, need))
                if not chunk:
                    self._closed = True
                    break
                body.extend(chunk)
                need -= len(chunk)
            if need == 0:
                self._buf = bytearray(remainder[content_length:])
            else:
                self._buf = bytearray()

        if close_after:
            self._closed = True

        return bytes(body)

    def _drain_to_header(self) -> tuple[str, bytes]:
        """Read from the socket until the header/body separator is in
        the buffer; return ``(headers_text, body_bytes_already_read)``.
        """
        while True:
            idx = self._buf.find(b"\r\n\r\n")
            if idx >= 0:
                head = bytes(self._buf[:idx]).decode("latin-1", errors="replace")
                remainder = bytes(self._buf[idx + 4:])
                self._buf = bytearray()
                return head, remainder
            chunk = self._tls.recv(65536)
            if not chunk:
                self._closed = True
                raise OSError("DoH server closed before headers")
            self._buf.extend(chunk)

    def _read_chunked(self, already: bytes) -> tuple[bytes, int]:
        """Decode a chunked body, possibly starting with some bytes we
        already read while draining headers.  Returns
        ``(body, bytes_consumed_from_already)``.
        """
        buf = bytearray(already)
        out = bytearray()
        cursor = 0
        while True:
            while b"\r\n" not in buf[cursor:]:
                chunk = self._tls.recv(65536)
                if not chunk:
                    self._closed = True
                    raise OSError("DoH server closed mid-chunk")
                buf.extend(chunk)
            size_end = buf.index(b"\r\n", cursor)
            try:
                size = int(bytes(buf[cursor:size_end]).split(b";", 1)[0], 16)
            except ValueError as exc:
                raise OSError(f"malformed chunk size: {exc}") from exc
            cursor = size_end + 2
            if size == 0:
                # Trailing CRLF after the zero-length final chunk.
                while len(buf) - cursor < 2:
                    chunk = self._tls.recv(65536)
                    if not chunk:
                        self._closed = True
                        break
                    buf.extend(chunk)
                cursor += 2
                return bytes(out), cursor
            while len(buf) - cursor < size + 2:
                chunk = self._tls.recv(65536)
                if not chunk:
                    self._closed = True
                    raise OSError("DoH server closed in chunk body")
                buf.extend(chunk)
            out.extend(buf[cursor:cursor + size])
            cursor += size + 2


class DoHConnectionPool:
    """Bounded pool of keep-alive DoH connections to one endpoint.

    The pool is LIFO so the most-recently-released (and therefore most
    likely still healthy) connection is reused first.  When the caller
    releases a connection that the server has marked ``Connection:
    close``, the pool discards it instead of reusing it.
    """

    def __init__(
        self,
        endpoint: DoHEndpoint,
        *,
        timeout_s: float = 5.0,
        max_size: int = 8,
    ) -> None:
        self._endpoint = endpoint
        self._timeout = timeout_s
        self._max = max(1, int(max_size))
        self._ctx = ssl.create_default_context()
        # Cryptographic identity on DoH is not optional: a transparent
        # man-in-the-middle on UDP-53 (the exact class of adversary we
        # are trying to bypass) would happily substitute its own
        # "DoH" response and pin browser name resolution to attacker
        # IPs.  ``check_hostname`` + ``verify_mode = CERT_REQUIRED``
        # (the defaults of :func:`ssl.create_default_context`) pin the
        # public resolver's certificate.  Endpoints without a
        # ``hostname`` field behave insecurely and are refused at
        # configuration load time, not silently downgraded here.
        if endpoint.hostname:
            self._ctx.check_hostname = True
            self._ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            # Legacy / user-supplied endpoint without a verified name.
            # We still honour it — some users intentionally aim DoH at
            # a private resolver on the LAN — but log loudly so the
            # configuration drift is obvious.
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE
            logger.warning(
                "DoH endpoint %s has no hostname set; certificate "
                "verification is DISABLED.  A transparent MITM on DoH "
                "traffic can silently redirect every DNS query.  Add a "
                "`hostname = \"...\"` field in settings or use a shipped "
                "default.", endpoint.ip,
            )
        self._idle: queue.LifoQueue[_DoHConnection] = queue.LifoQueue()
        self._closed = False

    @property
    def endpoint(self) -> DoHEndpoint:
        return self._endpoint

    def query(self, wire: bytes) -> bytes:
        """Forward one query.  Retries exactly once on a broken keep-alive."""
        for attempt in (0, 1):
            conn = self._acquire(force_new=(attempt == 1))
            try:
                response = conn.query(wire)
            except (OSError, ssl.SSLError) as exc:
                conn.close()
                if attempt == 1:
                    raise
                logger.debug(
                    "DoH keep-alive broke on attempt %d (%s); retrying fresh",
                    attempt, exc,
                )
                continue
            if conn.is_open():
                self._release(conn)
            else:
                conn.close()
            return response
        raise OSError("DoH pool: unreachable retry state")

    def close(self) -> None:
        """Drain every idle connection.  Safe to call multiple times."""
        self._closed = True
        while True:
            try:
                conn = self._idle.get_nowait()
            except queue.Empty:
                break
            conn.close()

    def warm_up(self, count: int | None = None) -> int:
        """Open *count* keep-alive connections up-front and park them in
        the pool, so the first request burst doesn't pay the TLS
        handshake RTT.

        Returns the number of connections that actually came up.  Fewer
        than requested is not fatal — the pool lazily opens missing
        sockets on demand, and the primary benefit of warming is just
        shortening the cold-start window.
        """
        if self._closed:
            return 0
        target = self._max if count is None else max(0, min(int(count), self._max))
        opened = 0
        for _ in range(target):
            try:
                conn = _DoHConnection(self._endpoint, self._timeout, self._ctx)
            except (OSError, ssl.SSLError) as exc:
                logger.debug(
                    "DoH warm-up failed after %d/%d connections: %s",
                    opened, target, exc,
                )
                break
            self._idle.put(conn)
            opened += 1
        return opened

    # Internal -----------------------------------------------------------

    def _acquire(self, *, force_new: bool) -> _DoHConnection:
        if not force_new:
            while True:
                try:
                    conn = self._idle.get_nowait()
                except queue.Empty:
                    break
                if conn.is_open():
                    return conn
                conn.close()
        return _DoHConnection(self._endpoint, self._timeout, self._ctx)

    def _release(self, conn: _DoHConnection) -> None:
        if self._closed:
            conn.close()
            return
        self._idle.put(conn)
        # Trim overflow.  ``LifoQueue`` is unbounded; we enforce the
        # cap on release rather than on acquire so a short burst of
        # concurrent queries can temporarily exceed ``_max`` without
        # serialising.
        while self._idle.qsize() > self._max:
            try:
                victim = self._idle.get_nowait()
            except queue.Empty:
                break
            victim.close()


# ---------------------------------------------------------------------------
# Public client facade
# ---------------------------------------------------------------------------

class DoHClient:
    """DoH POST client backed by a keep-alive connection pool.

    The socket targets the resolver's IP address directly (so no
    bootstrap DNS is needed) but the TLS handshake still presents and
    verifies the configured ``hostname`` — we specifically do *not*
    skip certificate validation, because a transparent middlebox on
    UDP-53 is exactly the adversary this whole program is designed to
    defeat, and letting it also silently substitute our DoH answers
    would turn the bypass into an attack vector on the user.  When an
    endpoint is configured without a ``hostname`` (explicit local
    override) the underlying :class:`DoHConnectionPool` downgrades to
    unverified TLS and logs a warning.
    """

    def __init__(
        self,
        endpoint: DoHEndpoint,
        timeout_s: float = 5.0,
        *,
        pool_size: int = 8,
    ):
        self._endpoint = endpoint
        self._timeout = timeout_s
        self._pool = DoHConnectionPool(
            endpoint, timeout_s=timeout_s, max_size=pool_size,
        )

    def query(self, wire: bytes) -> bytes:
        return self._pool.query(wire)

    def warm_up(self, count: int | None = None) -> int:
        """Pre-open pooled keep-alive connections.  See
        :meth:`DoHConnectionPool.warm_up`.
        """
        return self._pool.warm_up(count)

    def close(self) -> None:
        """Release all pooled sockets.  Called from engine shutdown."""
        self._pool.close()

    def __repr__(self) -> str:
        return f"DoHClient({self._endpoint.ip}:{self._endpoint.port})"


# ---------------------------------------------------------------------------
# Linux DNS stub server
# ---------------------------------------------------------------------------

class DNSStubServer:
    """Listens on (addr, 53) UDP+TCP, forwards each query via *resolver*.

    ``bind_addresses`` accepts either a single address string (legacy
    single-stack behaviour, kept for the Linux engine which binds a
    single loopback) or an iterable of addresses.  Each address is
    bound on both UDP and TCP; a bind failure on any one address is
    logged and skipped so a missing IPv6 stack does not prevent the
    IPv4 stub from starting.

    A small in-front :class:`DnsCache` (injected via ``cache``) is
    consulted before DoH forwarding so a burst of identical queries
    from parallel connections does not hit the upstream resolver more
    than once per TTL window.
    """

    def __init__(
        self,
        *,
        bind_address: str | None = None,
        bind_addresses: "Iterable[str] | None" = None,
        bind_port: int,
        primary: DoHClient,
        fallback: DoHClient | None = None,
        cache: "DnsCache | None" = None,
    ):
        if bind_addresses is None:
            if bind_address is None:
                raise ValueError("bind_address or bind_addresses required")
            addrs: list[str] = [bind_address]
        else:
            addrs = [a for a in bind_addresses if a]
            if not addrs:
                raise ValueError("bind_addresses is empty")
        self._addresses: list[str] = addrs
        self._port = bind_port
        self._primary = primary
        self._fallback = fallback
        self._cache = cache
        self._udp_socks: list[socket.socket] = []
        self._tcp_socks: list[socket.socket] = []
        self._running = False
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        bound: list[str] = []
        for addr in self._addresses:
            family = socket.AF_INET6 if ":" in addr else socket.AF_INET
            try:
                udp = socket.socket(family, socket.SOCK_DGRAM)
                udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    udp.bind((addr, self._port, 0, 0))
                else:
                    udp.bind((addr, self._port))
                self._udp_socks.append(udp)

                tcp = socket.socket(family, socket.SOCK_STREAM)
                tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    tcp.bind((addr, self._port, 0, 0))
                else:
                    tcp.bind((addr, self._port))
                tcp.listen(64)
                self._tcp_socks.append(tcp)
                bound.append(addr)
            except OSError as exc:
                logger.warning("DNS stub bind %s:%d failed: %s",
                               addr, self._port, exc)
                continue

        if not bound:
            raise OSError(f"DNS stub: no address could be bound on :{self._port}")

        self._running = True
        for sock in list(self._udp_socks):
            t = threading.Thread(
                target=self._serve_udp, args=(sock,), name="dns-udp", daemon=True,
            )
            t.start()
            self._threads.append(t)
        for sock in list(self._tcp_socks):
            t = threading.Thread(
                target=self._serve_tcp, args=(sock,), name="dns-tcp", daemon=True,
            )
            t.start()
            self._threads.append(t)
        logger.info("DNS stub listening on %s port %d (DoH forwarder)",
                    ",".join(bound), self._port)

    def stop(self) -> None:
        self._running = False
        for s in (*self._udp_socks, *self._tcp_socks):
            try:
                s.close()
            except OSError:
                pass
        self._udp_socks.clear()
        self._tcp_socks.clear()
        for t in self._threads:
            t.join(timeout=2)
        self._threads.clear()

    def _serve_udp(self, sock: socket.socket) -> None:
        while self._running:
            try:
                sock.settimeout(1.0)
                data, peer = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_udp,
                args=(sock, data, peer),
                daemon=True,
            ).start()

    def _handle_udp(self, sock: socket.socket, data: bytes, peer: tuple) -> None:
        response = self._resolve(data)
        if response:
            try:
                sock.sendto(response, peer)
            except OSError:
                pass

    def _serve_tcp(self, sock: socket.socket) -> None:
        while self._running:
            try:
                sock.settimeout(1.0)
                client, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_tcp, args=(client,), daemon=True
            ).start()

    def _handle_tcp(self, client: socket.socket) -> None:
        try:
            client.settimeout(5)
            header = client.recv(2)
            if len(header) < 2:
                return
            length = struct.unpack("!H", header)[0]
            payload = b""
            while len(payload) < length:
                chunk = client.recv(length - len(payload))
                if not chunk:
                    return
                payload += chunk

            response = self._resolve(payload)
            if response:
                client.sendall(struct.pack("!H", len(response)) + response)
        except OSError:
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    def _resolve(self, wire: bytes) -> bytes:
        if self._cache is not None:
            # Dedup + TTL cache in one call: parallel duplicate queries
            # (common during a page load's DNS burst) collapse onto the
            # leader's DoH round-trip instead of each racing the upstream
            # resolver independently.
            return self._cache.resolve(wire, self._resolve_direct)
        return self._resolve_direct(wire)

    def _resolve_direct(self, wire: bytes) -> bytes:
        for client in (self._primary, self._fallback):
            if client is None:
                continue
            try:
                response = client.query(wire)
            except OSError as exc:
                logger.debug("DoH forward failed via %s: %s", client, exc)
                continue
            return response
        return b""
