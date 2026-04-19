# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Single source of configuration: defaults < TOML file < environment < CLI.

No hostnames, domains or ISP-specific values are hard-coded here.  The only
literals are generic public IPs (1.1.1.1 as fallback DoH resolver) and local
proxy ports.  Everything else is user-controlled.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable, Literal, Sequence

try:
    import tomllib as _toml
except ModuleNotFoundError:
    import tomli as _toml  # type: ignore[no-redef]


DNSMode = Literal["doh", "altport", "off"]


@dataclass(frozen=True)
class DNSSettings:
    mode: DNSMode = "doh"
    # Public DoH resolver addressed by IP, but certificate-verified
    # against a pinned hostname so a transparent MITM cannot substitute
    # its own DNS answers.  The hostname is the SNI we present on the
    # wire and the name we match the peer certificate against.  DoH
    # traffic naturally traverses our own TLS proxy and inherits its
    # fragmentation, so the SNI is never leaked to a DPI middlebox.
    #
    # Resolver selection rationale.  Three public DoH endpoints were
    # evaluated on a DPI-heavy consumer ISP during development:
    #   * Cloudflare (1.1.1.1, cloudflare-dns.com) — TLS handshake is
    #     aggressively interrupted by the transit DPI with an injected
    #     ``0x15 0x03 0x03`` alert, and *no* ClientHello fragmentation
    #     strategy in our fallback list currently survives it.  Keeping
    #     Cloudflare as a primary leaves the engine without DNS on the
    #     exact networks it is most needed on.
    #   * Quad9 (9.9.9.9, dns.quad9.net) — TLS works, but Quad9 enforces
    #     RFC 8484 §5.1 strictly and rejects HTTP/1.1 requests with
    #     ``400 Bad Request``.  Our keep-alive pool is HTTP/1.1, so
    #     every query turns into an empty body and falls through to
    #     the ISP's resolver (the poisoning we are trying to defeat).
    #   * Google (8.8.8.8, dns.google) — TLS survives the ISP without
    #     fragmentation and the server speaks HTTP/1.1 DoH natively.
    #
    # Google is therefore the primary; Cloudflare is the fallback only
    # because it also speaks HTTP/1.1 — on networks that DO let the
    # Cloudflare TLS handshake through, it keeps us resilient to a
    # Google outage.  Users who want a different pair configure
    # `doh_endpoint_*` / `doh_fallback_*` freely.
    doh_endpoint_ip: str = "8.8.8.8"
    doh_endpoint_hostname: str = "dns.google"
    doh_endpoint_path: str = "/dns-query"
    # Secondary is tried if primary fails health check.
    doh_fallback_ip: str = "1.1.1.1"
    doh_fallback_hostname: str = "cloudflare-dns.com"
    # Local stub resolver address written into /etc/resolv.conf.
    stub_address: str = "127.0.0.53"
    stub_port: int = 53
    # For mode="altport": user must provide both.
    altport_server: str = ""
    altport_port: int = 0


@dataclass(frozen=True)
class TLSSettings:
    proxy_port: int = 4443
    proxy_mark: int = 200
    # Default strategy applied when a SNI is first seen.  Anything in
    # `strategy.py::Strategy.parse` grammar.
    default_strategy: str = "record:2"
    # Ordered fallbacks for runtime discovery.  Order matters: lightest to
    # heaviest.
    fallback_strategies: tuple[str, ...] = (
        "record:2",
        "record:1",
        "record:sni-mid",
        "tcp:sni-mid",
        "record:half",
        "chunked:40",
    )
    # Connection attempt timeout during discovery.
    probe_timeout_s: float = 3.0
    # Minimum bytes of TLS handshake reply (content-type 0x16) needed to
    # count a strategy as successful — protects against single-byte probes.
    success_min_bytes: int = 6
    # Cache lives on tmpfs by default: it is auto-wiped on reboot, and
    # explicitly wiped on every graceful shutdown (see engine.run).  Users
    # who want per-boot persistence can override this to a disk path in
    # their config — but the shutdown-wipe still applies, regardless.
    cache_path: str = "/run/whydpi/strategies.json"
    # Hosts for which the ClientHello is forwarded unchanged.  Runtime-learned;
    # user can pre-seed via config.
    user_passthrough_sni: tuple[str, ...] = ()


@dataclass(frozen=True)
class NetSettings:
    ipv6_enabled: bool = True
    block_quic: bool = True
    # CIDRs for which port 443 bypasses the proxy entirely (rare).
    bypass_cidrs_v4: tuple[str, ...] = ()
    bypass_cidrs_v6: tuple[str, ...] = ()


@dataclass(frozen=True)
class Settings:
    dns: DNSSettings = field(default_factory=DNSSettings)
    tls: TLSSettings = field(default_factory=TLSSettings)
    net: NetSettings = field(default_factory=NetSettings)
    # Optional user-supplied hosts for a one-off pre-flight probe at start.
    # Empty means: skip probe, enter adaptive mode directly.
    probe_targets: tuple[str, ...] = ()
    verbose: bool = False


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_PATH = "~/.config/whydpi/config.toml"
ENV_PREFIX = "WHYDPI_"


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(ENV_PREFIX + name)
    return value if value not in (None, "") else default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(ENV_PREFIX + name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_tuple(name: str) -> tuple[str, ...] | None:
    raw = os.environ.get(ENV_PREFIX + name)
    if raw is None:
        return None
    return tuple(x.strip() for x in raw.split(",") if x.strip())


def _load_toml(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("rb") as fh:
        return _toml.load(fh)


def _merge_dns(base: DNSSettings, data: dict) -> DNSSettings:
    changes: dict = {}
    for key in (
        "mode",
        "doh_endpoint_ip",
        "doh_endpoint_hostname",
        "doh_endpoint_path",
        "doh_fallback_ip",
        "doh_fallback_hostname",
        "stub_address",
        "altport_server",
    ):
        if key in data:
            changes[key] = data[key]
    if "stub_port" in data:
        changes["stub_port"] = int(data["stub_port"])
    if "altport_port" in data:
        changes["altport_port"] = int(data["altport_port"])
    return replace(base, **changes) if changes else base


def _merge_tls(base: TLSSettings, data: dict) -> TLSSettings:
    changes: dict = {}
    for key in ("default_strategy", "cache_path"):
        if key in data:
            changes[key] = data[key]
    for key in ("proxy_port", "proxy_mark", "success_min_bytes"):
        if key in data:
            changes[key] = int(data[key])
    if "probe_timeout_s" in data:
        changes["probe_timeout_s"] = float(data["probe_timeout_s"])
    if "fallback_strategies" in data:
        changes["fallback_strategies"] = tuple(data["fallback_strategies"])
    if "user_passthrough_sni" in data:
        changes["user_passthrough_sni"] = tuple(
            s.lower().lstrip(".") for s in data["user_passthrough_sni"]
        )
    return replace(base, **changes) if changes else base


def _merge_net(base: NetSettings, data: dict) -> NetSettings:
    changes: dict = {}
    for key in ("ipv6_enabled", "block_quic"):
        if key in data:
            changes[key] = bool(data[key])
    for key in ("bypass_cidrs_v4", "bypass_cidrs_v6"):
        if key in data:
            changes[key] = tuple(data[key])
    return replace(base, **changes) if changes else base


def _apply_env(s: Settings) -> Settings:
    dns = replace(
        s.dns,
        mode=_env("DNS_MODE", s.dns.mode),  # type: ignore[arg-type]
        doh_endpoint_ip=_env("DOH_IP", s.dns.doh_endpoint_ip),
        doh_endpoint_hostname=_env("DOH_HOSTNAME", s.dns.doh_endpoint_hostname),
        doh_endpoint_path=_env("DOH_PATH", s.dns.doh_endpoint_path),
        doh_fallback_ip=_env("DOH_FALLBACK_IP", s.dns.doh_fallback_ip),
        doh_fallback_hostname=_env("DOH_FALLBACK_HOSTNAME", s.dns.doh_fallback_hostname),
        altport_server=_env("ALTPORT_SERVER", s.dns.altport_server),
        altport_port=int(_env("ALTPORT_PORT", str(s.dns.altport_port)) or 0),
    )

    tls_strategies = _env_tuple("FALLBACK")
    tls = replace(
        s.tls,
        default_strategy=_env("STRATEGY", s.tls.default_strategy),
        fallback_strategies=tls_strategies or s.tls.fallback_strategies,
        cache_path=_env("CACHE_PATH", s.tls.cache_path),
        user_passthrough_sni=(
            tuple(x.lower().lstrip(".") for x in (_env_tuple("PASSTHROUGH_SNI") or ()))
            or s.tls.user_passthrough_sni
        ),
    )

    net = replace(
        s.net,
        ipv6_enabled=_env_bool("IPV6", s.net.ipv6_enabled),
        block_quic=_env_bool("BLOCK_QUIC", s.net.block_quic),
        bypass_cidrs_v4=_env_tuple("BYPASS_V4") or s.net.bypass_cidrs_v4,
        bypass_cidrs_v6=_env_tuple("BYPASS_V6") or s.net.bypass_cidrs_v6,
    )

    probe = _env_tuple("PROBE_TARGETS")
    return replace(
        s,
        dns=dns,
        tls=tls,
        net=net,
        probe_targets=probe if probe is not None else s.probe_targets,
    )


def load_settings(config_path: str | None = None) -> Settings:
    path = Path(os.path.expanduser(config_path or DEFAULT_CONFIG_PATH))
    data = _load_toml(path)

    base = Settings()
    merged = replace(
        base,
        dns=_merge_dns(base.dns, data.get("dns", {})),
        tls=_merge_tls(base.tls, data.get("tls", {})),
        net=_merge_net(base.net, data.get("net", {})),
        probe_targets=tuple(data.get("probe_targets", ())),
    )
    return _apply_env(merged)


def apply_cli_overrides(s: Settings, *, probe_targets: Sequence[str] | None = None,
                        verbose: bool = False, dns_mode: str | None = None) -> Settings:
    changes: dict = {}
    if probe_targets is not None:
        changes["probe_targets"] = tuple(probe_targets)
    if verbose:
        changes["verbose"] = True
    if dns_mode:
        changes["dns"] = replace(s.dns, mode=dns_mode)  # type: ignore[arg-type]
    return replace(s, **changes) if changes else s


def cache_path(s: Settings) -> Path:
    return Path(os.path.expanduser(s.tls.cache_path))


def passthrough_contains(suffixes: Iterable[str], host: str) -> bool:
    if not host:
        return False
    h = host.lower().strip(".")
    for suf in suffixes:
        suf = suf.lower().lstrip(".")
        if suf and (h == suf or h.endswith("." + suf)):
            return True
    return False
