# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Windows engine — WinDivert packet shaper + WinDivert DNS hijacker.

Design mirror
=============
This module is a structural one-to-one mirror of
:mod:`whydpi.platforms.linux`.  The Linux engine installs two
netfilter primitives (``REDIRECT`` for TCP/443, ``DNAT`` for UDP/53)
and lets a userspace proxy + DoH stub do the real work.  Windows has
no netfilter, but it does have WinDivert, which exposes the same
capability one layer deeper:

======================  =================================  =======================
Linux primitive         Windows equivalent                 whyDPI module
======================  =================================  =======================
iptables REDIRECT 443   WinDivert TCP/443 shaper           :mod:`..system.windivert`
iptables DNAT 53        WinDivert UDP/53 hijacker          :mod:`..system.dns_redirect_windows`
/etc/resolv.conf edit   *(not needed — hijack is wire)*    —
======================  =================================  =======================

No ``netsh`` is ever executed.  No NRPT policy is ever written.  No
Windows Firewall rule is ever added.  The driver handles live as long
as the tray does; close them and the system is exactly the state it
was in before whyDPI started — the same invariant Linux provides by
running ``iptables -D`` on cleanup.

Cross-platform modules (strategy parsing, per-SNI cache, DoH client,
privacy-preserving cache wipe on shutdown) are imported unchanged.
"""

from __future__ import annotations

import logging
import signal
import time
from dataclasses import dataclass
from typing import Callable

from ..core.cache import StrategyCache
from ..core.strategy import Strategy, parse_fallback
from ..net.dns import DoHClient, DoHEndpoint
from ..net.dns_cache import DnsCache
from ..settings import Settings, cache_path
from ..system.dns_redirect_windows import PacketDnsHijacker
from ..system.windivert import PacketShaper

logger = logging.getLogger(__name__)


@dataclass
class _Runtime:
    shaper: PacketShaper
    dns: PacketDnsHijacker | None
    cache: StrategyCache
    dns_cache: DnsCache
    doh_clients: tuple[DoHClient, ...]


def _flush_dns_cache() -> None:
    """Best-effort equivalent of ``ipconfig /flushdns``.

    The Win32 symbol ``DnsFlushResolverCache`` lives in ``dnsapi.dll``
    and takes no arguments; it clears the per-user DNS client cache the
    Service Control Manager's *Dnscache* service keeps in memory.  Any
    failure is silently swallowed — the engine must start even on
    systems where the symbol is absent or access-denied.
    """
    try:
        import ctypes  # local: Windows-only usage

        dnsapi = ctypes.WinDLL("dnsapi.dll", use_last_error=True)
        dnsapi.DnsFlushResolverCache()
        logger.info(
            "DNS resolver cache flushed; poisoned pre-launch entries "
            "cleared before first query",
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("DnsFlushResolverCache skipped: %s", exc)


def _build_doh_client(ip: str, hostname: str, path: str, timeout: float) -> DoHClient:
    return DoHClient(
        DoHEndpoint(ip=ip, hostname=hostname or None, path=path),
        timeout_s=timeout,
    )


def _build_dns_hijacker(
    settings: Settings,
    dns_cache: DnsCache,
) -> tuple[PacketDnsHijacker | None, tuple[DoHClient, ...]]:
    """Build the packet-layer DNS hijacker, if enabled.

    Honours ``settings.dns.mode``:

    * ``doh``   → hijacker forwards queries over DoH (default).
    * other     → hijacker disabled; UDP/53 flows to whatever resolver
                  the adapter is configured for (ISP DNS, typically).
                  Use this for isolated debugging of the shaper alone.

    Returns the hijacker (or ``None``) plus the sequence of DoH clients
    the caller must close on shutdown — the hijacker owns none of them
    itself, so the engine keeps an explicit handle for cleanup.
    """
    if settings.dns.mode != "doh":
        return None, ()
    primary = _build_doh_client(
        settings.dns.doh_endpoint_ip,
        settings.dns.doh_endpoint_hostname,
        settings.dns.doh_endpoint_path,
        5.0,
    )
    fallback = None
    clients: list[DoHClient] = [primary]
    if settings.dns.doh_fallback_ip:
        fallback = _build_doh_client(
            settings.dns.doh_fallback_ip,
            settings.dns.doh_fallback_hostname,
            settings.dns.doh_endpoint_path,
            5.0,
        )
        clients.append(fallback)
    return (
        PacketDnsHijacker(primary=primary, fallback=fallback, cache=dns_cache),
        tuple(clients),
    )


def _build_runtime(settings: Settings) -> _Runtime:
    cache = StrategyCache.load(cache_path(settings))
    dns_cache = DnsCache()

    default_strategy = Strategy.parse(settings.tls.default_strategy)
    fallbacks = parse_fallback(settings.tls.fallback_strategies)

    shaper = PacketShaper(
        default_strategy=default_strategy,
        fallbacks=fallbacks,
        cache=cache,
        block_quic=settings.net.block_quic,
        probe_timeout_s=settings.tls.probe_timeout_s,
        success_min_bytes=settings.tls.success_min_bytes,
        decoy_sni=settings.tls.decoy_sni,
    )

    dns, doh_clients = _build_dns_hijacker(settings, dns_cache)

    return _Runtime(
        shaper=shaper,
        dns=dns,
        cache=cache,
        dns_cache=dns_cache,
        doh_clients=doh_clients,
    )


def run(settings: Settings, *, configure_resolver: bool,
        block_until: Callable[[], None] | None = None) -> int:
    # ``configure_resolver`` is a Linux-era knob; on Windows there is
    # no resolver to configure because the hijacker replaces the
    # resolver path at the packet layer.  We accept the parameter to
    # keep the engine signature platform-agnostic.
    del configure_resolver

    runtime = _build_runtime(settings)

    try:
        # Order matters: bring the DNS hijacker up *before* the shaper,
        # so the first TLS ClientHello the shaper sees has already been
        # preceded by a DNS reply coming from our own resolver.  Either
        # order is correct, but this one avoids the very first browser
        # connection racing with DNS and landing on an ISP-hijacked IP.
        if runtime.dns is not None:
            runtime.dns.start()
        runtime.shaper.start()

        # Wipe Windows' user-mode DNS resolver cache so poisoned entries
        # left behind by the ISP's transparent UDP-53 hijack before the
        # engine came up don't leak past our first DoH round-trip.  On
        # DPI-heavy consumer networks we routinely observe AAAA records
        # for blocked domains pinned to the ISP's own IPv6 block-page
        # range; every subsequent ``getaddrinfo`` in a user's browser /
        # desktop app hits this cache and reaches the block-page server
        # instead of the real origin — even though our packet-layer
        # hijacker is by then intercepting live UDP/53 traffic correctly.
        # Calling the kernel ``DnsFlushResolverCache`` routine forces the next
        # resolution to go through the wire, where we answer it from
        # our cert-pinned DoH upstream.  Failure is non-fatal: the
        # Win32 API is present on every supported Windows version, but
        # a missing symbol (e.g. on Wine) just means cold connections
        # might race the cache for a few seconds.
        _flush_dns_cache()

        # Pre-warm the DoH connection pool in the background: each idle
        # TLS socket we park here is one less ~100-200 ms handshake a
        # user's first page load has to pay for.  Warm-up runs off the
        # critical path because we've already accepted traffic, and
        # warm-up failure (network offline, upstream unreachable) is
        # non-fatal — the pool opens missing sockets lazily on demand.
        def _warm_pool() -> None:
            for client in runtime.doh_clients:
                try:
                    opened = client.warm_up()
                    logger.info("DoH pool pre-warmed: %s -> %d idle conns",
                                client, opened)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("DoH warm-up skipped (%s): %s", client, exc)

        if runtime.doh_clients:
            import threading as _t
            _t.Thread(target=_warm_pool, name="whydpi-doh-warm", daemon=True).start()

        logger.info("whyDPI running — Ctrl+C or SIGTERM to stop")

        (block_until or _wait_for_signal)()
        return 0

    except Exception as exc:
        logger.error("startup failed: %s", exc)
        return 1

    finally:
        logger.info("shutting down...")
        try:
            runtime.shaper.stop()
        except Exception as exc:  # noqa: BLE001
            logger.warning("shaper stop: %s", exc)
        if runtime.dns is not None:
            try:
                runtime.dns.stop()
            except Exception as exc:  # noqa: BLE001
                logger.warning("dns hijacker stop: %s", exc)
        # Privacy is the whole point of the "service stopped" contract:
        # strategy cache, DNS-answer cache, and keep-alive DoH sockets
        # all disappear in the same shutdown breath so no residue
        # survives the tray session.
        try:
            runtime.cache.wipe()
            logger.info("session cache wiped (privacy: no history kept)")
        except Exception as exc:  # noqa: BLE001
            logger.warning("cache wipe: %s", exc)
        try:
            runtime.dns_cache.wipe()
        except Exception as exc:  # noqa: BLE001
            logger.warning("dns cache wipe: %s", exc)
        for client in runtime.doh_clients:
            try:
                client.close()
            except Exception as exc:  # noqa: BLE001
                logger.warning("doh client close: %s", exc)


def stop_only(settings: Settings) -> int:
    """Idempotent cleanup.

    The Windows engine holds no persisted state: WinDivert handles live
    for the duration of the process and dissolve when the process
    exits.  ``whydpi stop`` therefore has nothing to undo and is
    retained solely for CLI compatibility with the Linux build, which
    still needs to reverse its iptables edits.
    """
    del settings
    return 0


def _wait_for_signal() -> None:
    stop = False

    def _handler(_signum, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)

    while not stop:
        time.sleep(1)
