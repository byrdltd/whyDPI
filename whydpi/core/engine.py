# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Lifecycle orchestrator — wires settings, proxy, DNS and netfilter."""

from __future__ import annotations

import logging
import signal
import time
from dataclasses import dataclass
from typing import Callable

from ..net.dns import DNSStubServer, DoHClient, DoHEndpoint
from ..net.proxy import TransparentTLSProxy
from ..settings import Settings, cache_path
from ..system import resolver as resolver_system
from ..system.netfilter import Netfilter, compose_rules
from .cache import StrategyCache
from .strategy import Strategy, parse_fallback


logger = logging.getLogger(__name__)


@dataclass
class Runtime:
    proxy: TransparentTLSProxy
    dns_stub: DNSStubServer | None
    netfilter: Netfilter
    cache: StrategyCache
    configure_resolver: bool
    resolver_servers: list[str]


def _build_doh_client(ip: str, path: str, timeout: float) -> DoHClient:
    return DoHClient(DoHEndpoint(ip=ip, path=path), timeout_s=timeout)


def _dns_stub(settings: Settings) -> DNSStubServer | None:
    if settings.dns.mode != "doh":
        return None
    primary = _build_doh_client(
        settings.dns.doh_endpoint_ip,
        settings.dns.doh_endpoint_path,
        5.0,
    )
    fallback = None
    if settings.dns.doh_fallback_ip:
        fallback = _build_doh_client(
            settings.dns.doh_fallback_ip,
            settings.dns.doh_endpoint_path,
            5.0,
        )
    return DNSStubServer(
        bind_address=settings.dns.stub_address,
        bind_port=settings.dns.stub_port,
        primary=primary,
        fallback=fallback,
    )


def build_runtime(settings: Settings, *, configure_resolver: bool) -> Runtime:
    cache = StrategyCache.load(cache_path(settings))

    default_strategy = Strategy.parse(settings.tls.default_strategy)
    fallbacks = parse_fallback(settings.tls.fallback_strategies)

    proxy = TransparentTLSProxy(
        port=settings.tls.proxy_port,
        proxy_mark=settings.tls.proxy_mark,
        default_strategy=default_strategy,
        fallbacks=fallbacks,
        cache=cache,
        timeout_s=settings.tls.probe_timeout_s,
        success_min_bytes=settings.tls.success_min_bytes,
        passthrough_sni=settings.tls.user_passthrough_sni,
        ipv6_enabled=settings.net.ipv6_enabled,
    )

    stub = _dns_stub(settings)

    dns_stub_address: str | None = None
    dns_stub_port: int = 53
    dns_altport: tuple[str, int, int] | None = None
    resolver_servers: list[str] = []

    if settings.dns.mode == "doh":
        dns_stub_address = settings.dns.stub_address
        dns_stub_port = settings.dns.stub_port
        resolver_servers = [settings.dns.stub_address]
    elif settings.dns.mode == "altport":
        if not settings.dns.altport_server or not settings.dns.altport_port:
            raise ValueError(
                "dns.mode='altport' requires dns.altport_server and dns.altport_port"
            )
        dns_altport = (
            settings.dns.altport_server,
            53,
            settings.dns.altport_port,
        )
        resolver_servers = [settings.dns.altport_server]

    rules = compose_rules(
        tls_port=settings.tls.proxy_port,
        tls_mark=settings.tls.proxy_mark,
        ipv6_enabled=settings.net.ipv6_enabled,
        block_quic=settings.net.block_quic,
        bypass_v4=settings.net.bypass_cidrs_v4,
        bypass_v6=settings.net.bypass_cidrs_v6,
        dns_stub_address=dns_stub_address,
        dns_stub_port=dns_stub_port,
        dns_altport=dns_altport,
    )

    return Runtime(
        proxy=proxy,
        dns_stub=stub,
        netfilter=Netfilter(rules),
        cache=cache,
        configure_resolver=configure_resolver and bool(resolver_servers),
        resolver_servers=resolver_servers,
    )


def run(settings: Settings, *, configure_resolver: bool,
        block_until: Callable[[], None] | None = None) -> int:
    runtime = build_runtime(settings, configure_resolver=configure_resolver)

    try:
        if runtime.dns_stub is not None:
            # systemd-resolved holds 127.0.0.53:53 on most modern distros.
            # Stop it before we try to bind our stub, otherwise startup races
            # with a ``EADDRINUSE``.
            resolver_system._stop_systemd_resolved()
            runtime.dns_stub.start()

        runtime.proxy.start()

        runtime.netfilter.apply()

        if runtime.configure_resolver:
            if not resolver_system.is_configured(runtime.resolver_servers):
                resolver_system.configure(runtime.resolver_servers)

        logger.info("whyDPI running — Ctrl+C or SIGTERM to stop")

        (block_until or _wait_for_signal)()
        return 0

    except Exception as exc:
        logger.error("startup failed: %s", exc)
        return 1

    finally:
        logger.info("shutting down...")
        try:
            runtime.netfilter.cleanup()
        except Exception as exc:
            logger.warning("netfilter cleanup: %s", exc)
        try:
            runtime.proxy.stop()
        except Exception as exc:
            logger.warning("proxy stop: %s", exc)
        if runtime.dns_stub is not None:
            try:
                runtime.dns_stub.stop()
            except Exception as exc:
                logger.warning("dns stub stop: %s", exc)
        # Privacy by default: on any graceful exit we erase the browsing
        # fingerprint we built up at runtime.  The cache file on tmpfs
        # (/run/whydpi/) is removed; in-memory state is cleared.  Combined
        # with tmpfs's own wipe-on-reboot behaviour this guarantees no
        # SNI history survives a shutdown.
        try:
            runtime.cache.wipe()
            logger.info("session cache wiped (privacy: no history kept)")
        except Exception as exc:
            logger.warning("cache wipe: %s", exc)


def _wait_for_signal() -> None:
    stop = False

    def _handler(_signum, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)

    while not stop:
        time.sleep(1)


def stop_only(settings: Settings) -> int:
    """Idempotent cleanup — remove any rules matching current settings."""
    runtime = build_runtime(settings, configure_resolver=False)
    runtime.netfilter.cleanup()
    return 0
