# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Command-line interface."""

from __future__ import annotations

import argparse
import logging
import os
import sys

from .core.cache import StrategyCache
from .core.discovery import discover_upstream
from .core.engine import run, stop_only
from .core.failure import format_summary
from .core.strategy import Strategy, parse_fallback
from .net.dns import DoHClient, DoHEndpoint, DoHResolver
from .net.tls_parser import build_minimal_client_hello, parse_client_hello
from .settings import Settings, apply_cli_overrides, cache_path, load_settings
from .system import resolver as resolver_system


logger = logging.getLogger("whydpi")


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s  %(message)s",
    )


def _require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        logger.error("whyDPI must run as root (sudo)")
        sys.exit(1)


def cmd_start(args: argparse.Namespace) -> int:
    _require_root()
    settings = load_settings(args.config)
    settings = apply_cli_overrides(
        settings,
        probe_targets=args.probe_targets,
        verbose=args.verbose,
        dns_mode=args.dns_mode,
    )
    _configure_logging(settings.verbose)

    if args.probe_targets:
        _preflight_probe(settings, args.probe_targets)

    return run(settings, configure_resolver=args.configure_dns)


def cmd_stop(args: argparse.Namespace) -> int:
    _require_root()
    settings = load_settings(args.config)
    _configure_logging(args.verbose)
    return stop_only(settings)


def cmd_dns_configure(args: argparse.Namespace) -> int:
    _require_root()
    settings = load_settings(args.config)
    _configure_logging(args.verbose)
    if settings.dns.mode == "off":
        logger.info("dns.mode='off' — nothing to configure")
        return 0
    servers = [settings.dns.stub_address] if settings.dns.mode == "doh" else [
        settings.dns.altport_server
    ]
    return 0 if resolver_system.configure(servers) else 1


def cmd_dns_restore(args: argparse.Namespace) -> int:
    _require_root()
    _configure_logging(args.verbose)
    return 0 if resolver_system.restore() else 1


def cmd_probe(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    _configure_logging(True)
    return _preflight_probe(settings, args.targets)


def cmd_cache(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    cache = StrategyCache.load(cache_path(settings))

    if args.subcmd == "list":
        hosts = sorted(cache.known_hosts())
        if not hosts:
            print("(cache empty)")
            return 0
        for host in hosts:
            entry = cache.get(host)
            if entry is None:
                continue
            kind = f"\tlast_fail={entry.last_failure_kind}" if entry.last_failure_kind else ""
            print(
                f"{host}\t{entry.strategy}\tsuccess={entry.successes} "
                f"fail={entry.failures}{kind}"
            )
        return 0

    if args.subcmd == "clear":
        for host in list(cache.known_hosts()):
            cache.forget(host)
        cache.flush()
        print("cache cleared")
        return 0

    if args.subcmd == "forget":
        for host in args.hosts:
            cache.forget(host)
        cache.flush()
        return 0

    return 1


def _build_probe_resolver(settings: Settings) -> tuple[DoHResolver | None, tuple[DoHClient, ...]]:
    """A standalone DoH resolver for the probe diagnostic.

    The running engine shares the stub's DoH clients with the proxy; the
    probe has no engine, so it builds its own short-lived clients from the
    same configured endpoints.  This lets ``whydpi probe`` exercise the exact
    upstream-IP rotation the live proxy uses — including surfacing CDN ranges
    the local resolver hides.  Returns ``(None, ())`` when DNS is off.
    """
    if settings.dns.mode == "off":
        return None, ()
    clients: list[DoHClient] = []
    for ip, hostname in (
        (settings.dns.doh_endpoint_ip, settings.dns.doh_endpoint_hostname),
        (settings.dns.doh_fallback_ip, settings.dns.doh_fallback_hostname),
    ):
        if not ip:
            continue
        try:
            clients.append(
                DoHClient(
                    DoHEndpoint(ip=ip, hostname=hostname or None,
                                path=settings.dns.doh_endpoint_path),
                    timeout_s=5.0,
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("probe DoH client %s skipped: %s", ip, exc)
    if not clients:
        return None, ()
    return DoHResolver(clients), tuple(clients)


def _preflight_probe(settings, targets: list[str]) -> int:
    if not targets:
        logger.error("probe requires at least one target host")
        return 1

    default = Strategy.parse(settings.tls.default_strategy)
    fallbacks = parse_fallback(settings.tls.fallback_strategies)
    alt_resolver, doh_clients = _build_probe_resolver(settings)

    any_failed = False
    try:
        for target in targets:
            hello = build_minimal_client_hello(target)
            view = parse_client_hello(hello)

            result = discover_upstream(
                sni=target,
                client_dest_ip=target,
                client_dest_port=443,
                hello_bytes=hello,
                hello_view=view,
                cached=None,
                default=default,
                fallbacks=fallbacks,
                proxy_mark=settings.tls.proxy_mark,
                timeout_s=settings.tls.probe_timeout_s,
                success_min_bytes=settings.tls.success_min_bytes,
                ipv6_enabled=settings.net.ipv6_enabled,
                probe_passthrough_first=settings.tls.probe_passthrough_first,
                accept_alert=True,
                alt_resolver=alt_resolver,
            )

            attempts = ", ".join(f"{lbl}={reason}" for lbl, reason in result.attempts)
            if result.strategy is None:
                summary = format_summary(result.failure_kind, result.attempts)
                endpoint = result.target.ip if result.target else "?"
                logger.warning(
                    "%s [%s]: NO STRATEGY kind=%s (%s)",
                    target, endpoint, result.failure_kind.value, summary,
                )
                any_failed = True
            else:
                endpoint = result.target.ip if result.target else "?"
                logger.info(
                    "%s [%s]: %s  (%s)",
                    target, endpoint, result.strategy.label(), attempts,
                )
            if result.upstream is not None:
                try:
                    result.upstream.close()
                except OSError:
                    pass
    finally:
        for client in doh_clients:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass

    return 1 if any_failed else 0


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", help="path to config.toml (default: ~/.config/whydpi/config.toml)")
    parser.add_argument("-v", "--verbose", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="whydpi",
        description=(
            "Educational DPI bypass — transparent TLS fragmentation + DoH. "
            "Set WHYDPI_TRACE=1 to log every intercepted TCP/443, UDP/443 "
            "and UDP/53 packet at INFO level (Windows-only, diagnostic)."
        ),
        epilog=(
            "Tray: set WHYDPI_SKIP_DISCLAIMER=1 only in CI/automation to skip "
            "the first-run acceptable-use dialog (not for end users)."
        ),
    )
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("start", help="start whyDPI")
    _add_common(p)
    p.add_argument("--configure-dns", action="store_true",
                   help="pin /etc/resolv.conf at startup")
    p.add_argument("--probe-targets", nargs="*", default=[],
                   help="hosts for an optional pre-flight probe")
    p.add_argument("--dns-mode", choices=["doh", "altport", "off"],
                   help="override dns.mode for this run")
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("stop", help="remove netfilter rules")
    _add_common(p)
    p.set_defaults(func=cmd_stop)

    p = sub.add_parser("dns-configure", help="pin /etc/resolv.conf to stub resolver")
    _add_common(p)
    p.set_defaults(func=cmd_dns_configure)

    p = sub.add_parser("dns-restore", help="restore original /etc/resolv.conf")
    _add_common(p)
    p.set_defaults(func=cmd_dns_restore)

    p = sub.add_parser("probe", help="probe hosts, report winning strategy per host")
    _add_common(p)
    p.add_argument("targets", nargs="+", help="host[:port] targets to probe")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("cache", help="inspect or prune the strategy cache")
    _add_common(p)
    cache_sub = p.add_subparsers(dest="subcmd", required=True)
    cache_sub.add_parser("list")
    cache_sub.add_parser("clear")
    forget = cache_sub.add_parser("forget")
    forget.add_argument("hosts", nargs="+")
    p.set_defaults(func=cmd_cache)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)
    rc = args.func(args)
    sys.exit(int(rc or 0))


if __name__ == "__main__":
    main()
