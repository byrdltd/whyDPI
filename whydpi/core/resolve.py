# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Build ordered upstream (ip, port) targets for a TLS connection."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable, Literal, Sequence


# An optional address source consulted before the system resolver.  Given a
# hostname and whether IPv6 is wanted, it returns raw IP strings.  whyDPI
# injects a DoH-backed implementation (see :class:`whydpi.net.dns.DoHResolver`)
# so alternates can include CDN anycast ranges the local/poisoned resolver
# hides; the callable form keeps :mod:`whydpi.core` free of any net imports.
AltResolver = Callable[[str, bool], Sequence[str]]


@dataclass(frozen=True)
class UpstreamTarget:
    ip: str
    port: int
    source: Literal["client", "dns"]


def client_target(client_ip: str, client_port: int) -> UpstreamTarget | None:
    """The address the browser already selected (``SO_ORIGINAL_DST``)."""
    ip = _resolve_client_ip(client_ip, client_port)
    if ip is None:
        return None
    return UpstreamTarget(ip=ip, port=client_port, source="client")


def dns_alternate_targets(
    sni: str,
    *,
    client_port: int,
    exclude_ips: set[str],
    ipv6_enabled: bool,
    max_alternates: int = 3,
    extra_resolver: "AltResolver | None" = None,
) -> tuple[UpstreamTarget, ...]:
    """Alternate A/AAAA targets, tried when the client-chosen IP is unusable.

    Pulling every CDN address on every connection stalls the proxy for tens of
    seconds (each dead edge pays a full discovery window), so alternates are
    capped and only consulted on a failing connection.

    Two address sources are merged, in priority order:

    1. *extra_resolver* (optional) — a diversified resolver, typically DoH
       across several upstreams.  It can surface CDN anycast ranges the local
       resolver hides or that an ISP poisons, which is the whole point when
       the block is on an IP *range* rather than the SNI.
    2. ``socket.getaddrinfo`` — the always-available system path (unchanged
       behaviour when no *extra_resolver* is supplied).

    Candidates are then ordered so addresses on a network prefix *different*
    from every excluded (already-failed) IP come first: if the block targets
    one anycast range, an address on another range is the one worth trying
    first.  This is a generic prefix heuristic — no range is ever hard-coded.
    """
    if max_alternates <= 0:
        return ()

    seen = set(exclude_ips)
    candidates: list[str] = []

    def _add(ip: str) -> None:
        if not ip or ip in seen:
            return
        if not ipv6_enabled and ":" in ip:
            return
        seen.add(ip)
        candidates.append(ip)

    if extra_resolver is not None:
        try:
            for ip in extra_resolver(sni, ipv6_enabled):
                _add(ip)
        except Exception:  # noqa: BLE001 — a resolver hiccup must not break discovery
            pass

    for family in ([socket.AF_INET, socket.AF_INET6] if ipv6_enabled else [socket.AF_INET]):
        try:
            infos = socket.getaddrinfo(
                sni,
                client_port,
                family=family,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except socket.gaierror:
            continue
        for info in infos:
            _add(info[4][0])

    blocked_prefixes = {_net_prefix(ip) for ip in exclude_ips}
    # Stable sort: a False (0) sort key keeps "fresh prefix" addresses ahead
    # of same-prefix siblings while preserving resolver order within a tier.
    candidates.sort(key=lambda ip: _net_prefix(ip) in blocked_prefixes)

    ordered = [
        UpstreamTarget(ip=ip, port=client_port, source="dns")
        for ip in candidates[:max_alternates]
    ]
    return tuple(ordered)


def _net_prefix(ip: str) -> str:
    """Coarse network identity for diversity ordering.

    IPv4 → first two octets (~/16), IPv6 → first two hextets (~/32).  This is
    deliberately coarse: it only needs to tell "same anycast block as the
    address that just failed" from "somewhere else", not to be a real subnet.
    """
    if ":" in ip:
        parts = ip.split(":")
        return ":".join(parts[:2])
    octets = ip.split(".")
    return ".".join(octets[:2])


def _resolve_client_ip(client_ip: str, client_port: int) -> str | None:
    if _is_ip(client_ip):
        return client_ip
    try:
        infos = socket.getaddrinfo(
            client_ip,
            client_port,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror:
        return None
    if not infos:
        return None
    return infos[0][4][0]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
