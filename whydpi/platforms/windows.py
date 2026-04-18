# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Windows engine — WinDivert packet shaper + netsh DNS control.

Mirrors :mod:`whydpi.platforms.linux` in shape but uses a packet-layer
fragmenter instead of a userspace proxy, because Windows has no
``iptables REDIRECT`` analogue that preserves the original destination
cheaply.

Everything that is intrinsically cross-platform — strategy parsing,
per-SNI cache, DoH stub resolver, privacy-preserving cache wipe on
shutdown — is imported unchanged from the shared modules.
"""

from __future__ import annotations

import logging
import signal
import time
from dataclasses import dataclass
from typing import Callable

from ..core.cache import StrategyCache
from ..core.strategy import Strategy, parse_fallback
from ..net.dns import DNSStubServer, DoHClient, DoHEndpoint
from ..settings import Settings, cache_path
from ..system.dns_windows import WindowsDnsManager
from ..system.windivert import PacketShaper

logger = logging.getLogger(__name__)


# Windows has no systemd-resolved to contend with, so we bind the stub
# on plain loopback.  The user's adapter DNS is pointed here by the
# WindowsDnsManager.
_WINDOWS_STUB_ADDRESS = "127.0.0.1"


@dataclass
class _Runtime:
    shaper: PacketShaper
    dns_stub: DNSStubServer | None
    dns_manager: WindowsDnsManager | None
    cache: StrategyCache
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
        bind_address=_WINDOWS_STUB_ADDRESS,
        bind_port=settings.dns.stub_port,
        primary=primary,
        fallback=fallback,
    )


def _build_runtime(settings: Settings, *, configure_resolver: bool) -> _Runtime:
    cache = StrategyCache.load(cache_path(settings))

    default_strategy = Strategy.parse(settings.tls.default_strategy)
    fallbacks = parse_fallback(settings.tls.fallback_strategies)

    shaper = PacketShaper(
        default_strategy=default_strategy,
        fallbacks=fallbacks,
        cache=cache,
    )

    stub = _dns_stub(settings)
    resolver_servers: list[str] = []
    if settings.dns.mode == "doh":
        resolver_servers = [_WINDOWS_STUB_ADDRESS]
    elif settings.dns.mode == "altport":
        if settings.dns.altport_server:
            resolver_servers = [settings.dns.altport_server]

    dns_manager = WindowsDnsManager() if (configure_resolver and resolver_servers) else None

    return _Runtime(
        shaper=shaper,
        dns_stub=stub,
        dns_manager=dns_manager,
        cache=cache,
        resolver_servers=resolver_servers,
    )


def run(settings: Settings, *, configure_resolver: bool,
        block_until: Callable[[], None] | None = None) -> int:
    runtime = _build_runtime(settings, configure_resolver=configure_resolver)

    try:
        if runtime.dns_stub is not None:
            runtime.dns_stub.start()

        runtime.shaper.start()

        if runtime.dns_manager is not None:
            if not runtime.dns_manager.is_configured(runtime.resolver_servers):
                runtime.dns_manager.configure(runtime.resolver_servers)

        logger.info("whyDPI running — Ctrl+C or SIGTERM to stop")

        (block_until or _wait_for_signal)()
        return 0

    except Exception as exc:
        logger.error("startup failed: %s", exc)
        return 1

    finally:
        logger.info("shutting down...")
        if runtime.dns_manager is not None:
            try:
                runtime.dns_manager.restore()
            except Exception as exc:  # noqa: BLE001
                logger.warning("DNS restore: %s", exc)
        try:
            runtime.shaper.stop()
        except Exception as exc:  # noqa: BLE001
            logger.warning("shaper stop: %s", exc)
        if runtime.dns_stub is not None:
            try:
                runtime.dns_stub.stop()
            except Exception as exc:  # noqa: BLE001
                logger.warning("dns stub stop: %s", exc)
        try:
            runtime.cache.wipe()
            logger.info("session cache wiped (privacy: no history kept)")
        except Exception as exc:  # noqa: BLE001
            logger.warning("cache wipe: %s", exc)


def stop_only(settings: Settings) -> int:
    """Idempotent cleanup — restore DNS from disk backup, if any.

    There are no firewall rules to tear down on Windows (the WinDivert
    driver is transient), so we only need to undo the adapter DNS
    changes.  The shaper exits with the process.
    """
    del settings
    manager = WindowsDnsManager()
    try:
        manager.restore()
    except Exception as exc:  # noqa: BLE001
        logger.warning("DNS restore: %s", exc)
        return 1
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
