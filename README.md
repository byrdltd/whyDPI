# whyDPI

Educational DPI bypass tool for Linux research environments.

whyDPI is a transparent TLS proxy and DNS forwarder.  It ships **zero
hard-coded hostnames, domains or ISP-specific resolvers**: what works for a
given destination is discovered at runtime, cached per-SNI, and refined when
conditions change.

## How it works

1. **Netfilter hijack** — iptables/ip6tables REDIRECT sends outbound
   TCP/443 to a local transparent proxy.  A small set of rules also blocks
   QUIC (UDP/443) so browsers fall back to TCP, and (optionally) redirects
   UDP+TCP/53 to a local DoH stub resolver.
2. **ClientHello shaping** — the proxy parses the ClientHello, identifies
   the SNI, then applies a fragmentation *strategy* before forwarding the
   bytes upstream.
3. **Adaptive discovery** — for each SNI, the proxy tries the cached
   winning strategy first, then the configured default, then a list of
   fallbacks.  A strategy is considered successful only when the upstream
   reply starts with a valid TLS handshake record (`content-type 0x16`);
   HTTP block pages (`H…`) and injected RSTs are ignored.  The winning
   strategy is persisted to `~/.cache/whydpi/strategies.json`.
4. **DoH forwarding** — the optional DNS stub forwards every query as a
   DoH POST to a user-configured resolver IP.  The DoH connection itself
   transits the TLS proxy, so DNS traffic inherits the same fragmentation.

## Strategies

A strategy is a tuple `(layer, offset)`:

| Spec | Meaning |
| --- | --- |
| `record:N`       | Re-frame the ClientHello as two TLS records, split at payload byte N |
| `record:sni-mid` | Same, but split in the middle of the SNI extension |
| `record:half`    | Same, split at the payload midpoint |
| `tcp:sni-mid`    | Keep one TLS record, split the TCP send at the SNI midpoint |
| `chunked:N`      | Split the raw bytes into N-byte TCP chunks |
| `passthrough`    | Forward unchanged (used automatically for SNIs that break under any strategy) |

## Installation

### Arch Linux (AUR)

Two AUR packages are published:

- [`whydpi`](https://aur.archlinux.org/packages/whydpi) — stable, built from the latest release tag (recommended)
- [`whydpi-git`](https://aur.archlinux.org/packages/whydpi-git) — tracks the `main` branch, always bleeding-edge

```bash
paru -S whydpi           # stable
# or: paru -S whydpi-git # bleeding-edge
sudo systemctl enable --now whydpi
```

### Debian / Ubuntu (PPA — coming soon)

```bash
# Planned:
# sudo add-apt-repository ppa:byrdltd/whydpi
# sudo apt install whydpi
```

A tested Debian source package lives in `packaging/debian/`.  Until the
PPA is live you can build your own `.deb` in a container —
see `packaging/debian/README.md`.

### Any Linux (from source)

```bash
git clone https://github.com/byrdltd/whyDPI.git
cd whyDPI
sudo ./install.sh
```

## Configuration

whyDPI reads `~/.config/whydpi/config.toml` at startup.  All values are
optional; env vars (`WHYDPI_*`) and CLI flags override the file.  A fully
explicit example:

```toml
[dns]
mode = "doh"            # "doh" | "altport" | "off"
doh_endpoint_ip = "1.1.1.1"
doh_endpoint_path = "/dns-query"
doh_fallback_ip = "9.9.9.9"
stub_address = "127.0.0.53"

[tls]
default_strategy = "record:2"
fallback_strategies = [
    "record:2", "record:1", "record:sni-mid",
    "tcp:sni-mid", "record:half", "chunked:40",
]
probe_timeout_s = 3.0
success_min_bytes = 6

[net]
ipv6_enabled = true
block_quic = true
```

## Commands

```bash
# start (optionally pin /etc/resolv.conf to the stub)
sudo whydpi start --configure-dns

# stop and remove rules
sudo whydpi stop

# inspect the per-SNI strategy cache
sudo whydpi cache list
sudo whydpi cache clear
sudo whydpi cache forget example.org

# stand-alone diagnostic: report the strategy each target needs
sudo whydpi probe example.org example.net

# DNS resolver
sudo whydpi dns-configure
sudo whydpi dns-restore
```

## System requirements

- Linux
- Python 3.10+ (`tomllib`; on 3.10 install `tomli` via `requirements.txt`)
- `iptables` or `iptables-nft` (IPv6 rules need `ip6tables`)
- Root privileges

## Notes

- No hostnames are shipped in code.  The DoH endpoint is an IP.  The SNI
  cache only contains hosts *you* have visited.
- A success in `whydpi probe` means the upstream produced a valid TLS
  handshake reply — not an HTTP 200.  Middlebox block pages and RSTs are
  rejected explicitly.
- IPv6 HTTPS is fully proxied (unlike v0.1.0 which blocked it).  Disable
  with `net.ipv6_enabled = false` if the upstream breaks IPv6.

## Disclaimer

For educational and research purposes only.  Use only where you are
authorized to test, and comply with applicable laws and network policies.
