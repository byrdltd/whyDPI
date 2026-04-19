# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Command-line interface."""

from __future__ import annotations

import argparse
import logging
import os
import socket
import sys

from .core.cache import StrategyCache
from .core.discovery import discover, order_candidates
from .core.engine import run, stop_only
from .core.strategy import Strategy, parse_fallback
from .net.tls_parser import build_minimal_client_hello, parse_client_hello
from .settings import apply_cli_overrides, cache_path, load_settings
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


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

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
            print(f"{host}\t{entry.strategy}\tsuccess={entry.successes} fail={entry.failures}")
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


# ---------------------------------------------------------------------------
# Pre-flight probe (diagnostic, no site names embedded)
# ---------------------------------------------------------------------------

def _preflight_probe(settings, targets: list[str]) -> int:
    if not targets:
        logger.error("probe requires at least one target host")
        return 1

    default = Strategy.parse(settings.tls.default_strategy)
    fallbacks = parse_fallback(settings.tls.fallback_strategies)

    any_failed = False
    for target in targets:
        try:
            infos = socket.getaddrinfo(target, 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            logger.error("%s: DNS resolution failed (%s)", target, exc)
            any_failed = True
            continue

        ip = infos[0][4][0]
        hello = build_minimal_client_hello(target)
        view = parse_client_hello(hello)
        candidates = order_candidates(None, default, fallbacks)

        result = discover(
            dest_ip=ip,
            dest_port=443,
            hello_bytes=hello,
            hello_view=view,
            candidates=candidates,
            proxy_mark=settings.tls.proxy_mark,
            timeout_s=settings.tls.probe_timeout_s,
            success_min_bytes=settings.tls.success_min_bytes,
            accept_alert=True,
        )

        attempts = ", ".join(f"{lbl}={reason}" for lbl, reason in result.attempts)
        if result.strategy is None:
            logger.warning("%s [%s]: NO STRATEGY  (%s)", target, ip, attempts)
            any_failed = True
        else:
            logger.info("%s [%s]: %s  (%s)", target, ip, result.strategy.label(), attempts)
        if result.upstream is not None:
            try:
                result.upstream.close()
            except OSError:
                pass

    return 1 if any_failed else 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

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
