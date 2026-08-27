# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Unified netfilter rule manager.

One declarative rule format, one runner, one apply/cleanup cycle.  Supports
both ``iptables`` and ``ip6tables`` families.  Rules are kept as ordered
lists; cleanup simply deletes the same rules in reverse, so the object is
idempotent across restarts.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from typing import Iterable, Literal, Sequence


logger = logging.getLogger(__name__)

Family = Literal["v4", "v6"]


@dataclass(frozen=True)
class Rule:
    family: Family
    table: str          # "nat", "filter", "mangle"
    chain: str          # "OUTPUT", "INPUT", ...
    match: tuple[str, ...]
    action: tuple[str, ...]
    position: Literal["append", "insert"] = "append"

    def _binary(self) -> str:
        name = "iptables" if self.family == "v4" else "ip6tables"
        return shutil.which(name) or name

    def _argv(self, op: str) -> list[str]:
        return [
            self._binary(),
            "-t", self.table,
            op, self.chain,
            *self.match,
            *self.action,
        ]

    def add_argv(self) -> list[str]:
        return self._argv("-I" if self.position == "insert" else "-A")

    def del_argv(self) -> list[str]:
        return self._argv("-D")


def _run(argv: Sequence[str], *, must_succeed: bool = False) -> bool:
    try:
        result = subprocess.run(list(argv), check=False, capture_output=True)
    except FileNotFoundError as exc:
        if must_succeed:
            raise
        logger.debug("netfilter binary missing: %s", exc)
        return False
    if must_succeed and result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, argv, result.stdout, result.stderr
        )
    return result.returncode == 0


class Netfilter:
    """Apply / revert a declarative set of rules atomically per-family."""

    def __init__(self, rules: Sequence[Rule]):
        self._rules = tuple(rules)
        self._applied: list[Rule] = []

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    def flush_matching(self) -> None:
        """Remove any prior copies of our rules before applying fresh ones."""
        for rule in self._rules:
            while _run(rule.del_argv()):
                pass

    def apply(self) -> None:
        self.flush_matching()
        applied: list[Rule] = []
        try:
            for rule in self._rules:
                _run(rule.add_argv(), must_succeed=True)
                applied.append(rule)
        except Exception:
            # Revert partial application
            for rule in reversed(applied):
                _run(rule.del_argv())
            raise
        self._applied = applied

    def cleanup(self) -> None:
        for rule in reversed(self._applied or list(self._rules)):
            while _run(rule.del_argv()):
                pass
        self._applied = []


# ---------------------------------------------------------------------------
# Rule builders (policy-agnostic)
# ---------------------------------------------------------------------------

def tls_redirect(*, port: int, mark: int, family: Family) -> Rule:
    return Rule(
        family=family,
        table="nat",
        chain="OUTPUT",
        match=(
            "-p", "tcp", "--dport", "443",
            "-m", "mark", "!", "--mark", str(mark),
        ),
        action=("-j", "REDIRECT", "--to-port", str(port)),
    )


def tls_bypass(cidr: str, family: Family) -> Rule:
    return Rule(
        family=family,
        table="nat",
        chain="OUTPUT",
        match=("-p", "tcp", "-d", cidr, "--dport", "443"),
        action=("-j", "RETURN"),
        position="insert",
    )


def dns_redirect(*, stub_address: str, stub_port: int, family: Family) -> Rule:
    """Redirect all outbound DNS (UDP+TCP/53) to our local stub resolver.

    Using REDIRECT keeps the destination-as-seen by the process unchanged,
    while actually landing on the stub.  Two rules per family (UDP and TCP)
    are inserted as separate Rule objects by the caller.
    """
    return Rule(
        family=family,
        table="nat",
        chain="OUTPUT",
        match=("-p", "udp", "--dport", "53",
               "!", "-d", stub_address),
        action=("-j", "DNAT", "--to-destination", f"{stub_address}:{stub_port}"),
    )


def dns_redirect_tcp(*, stub_address: str, stub_port: int, family: Family) -> Rule:
    return Rule(
        family=family,
        table="nat",
        chain="OUTPUT",
        match=("-p", "tcp", "--dport", "53",
               "!", "-d", stub_address),
        action=("-j", "DNAT", "--to-destination", f"{stub_address}:{stub_port}"),
    )


def dns_altport_rule(*, server: str, src_port: int, dst_port: int, family: Family,
                     proto: Literal["udp", "tcp"]) -> Rule:
    return Rule(
        family=family,
        table="nat",
        chain="OUTPUT",
        match=("-p", proto, "-d", server, "--dport", str(src_port)),
        action=("-j", "DNAT", "--to-destination", f"{server}:{dst_port}"),
    )


def quic_block(family: Family) -> Rule:
    reject = "icmp-port-unreachable" if family == "v4" else "icmp6-port-unreachable"
    return Rule(
        family=family,
        table="filter",
        chain="OUTPUT",
        match=("-p", "udp", "--dport", "443"),
        action=("-j", "REJECT", "--reject-with", reject),
        position="insert",
    )


def compose_rules(
    *,
    tls_port: int,
    tls_mark: int,
    ipv6_enabled: bool,
    block_quic: bool,
    bypass_v4: Iterable[str],
    bypass_v6: Iterable[str],
    dns_stub_address: str | None,
    dns_stub_port: int,
    dns_altport: tuple[str, int, int] | None,
) -> list[Rule]:
    """Produce the complete rule set for the active configuration."""
    rules: list[Rule] = []

    # QUIC must come before TLS redirect so UDP 443 never races an outbound
    # session.  Using insert positions them at the top of their chains.
    if block_quic:
        rules.append(quic_block("v4"))
        if ipv6_enabled:
            rules.append(quic_block("v6"))

    for cidr in bypass_v4:
        rules.append(tls_bypass(cidr, "v4"))
    if ipv6_enabled:
        for cidr in bypass_v6:
            rules.append(tls_bypass(cidr, "v6"))

    rules.append(tls_redirect(port=tls_port, mark=tls_mark, family="v4"))
    if ipv6_enabled:
        rules.append(tls_redirect(port=tls_port, mark=tls_mark, family="v6"))

    if dns_stub_address:
        rules.append(dns_redirect(
            stub_address=dns_stub_address, stub_port=dns_stub_port, family="v4"
        ))
        rules.append(dns_redirect_tcp(
            stub_address=dns_stub_address, stub_port=dns_stub_port, family="v4"
        ))
    if dns_altport:
        server, src, dst = dns_altport
        rules.append(dns_altport_rule(
            server=server, src_port=src, dst_port=dst, family="v4", proto="udp",
        ))
        rules.append(dns_altport_rule(
            server=server, src_port=src, dst_port=dst, family="v4", proto="tcp",
        ))

    return rules
