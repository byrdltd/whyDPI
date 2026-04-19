# Windows packaging

Builds two executables plus a single installer:

| Artifact                    | Purpose                                    |
|-----------------------------|--------------------------------------------|
| `whydpi-tray.exe`           | GUI tray icon (UAC-elevated on launch)     |
| `whydpi.exe`                | CLI, useful for troubleshooting            |
| `whydpi-<version>-setup.exe`| Inno Setup installer bundling both exes    |

## How CI builds it

The `windows` job of `.github/workflows/release.yml` runs on
`windows-latest` and:

1. Installs the package with its `[windows]` extras (pulls in
   `pydivert`, `pystray`, `Pillow`).
2. Calls PyInstaller twice — once for the tray entry and once for the
   CLI — with:
   * `--onefile --windowed --uac-admin` (tray),
   * `--onefile --console --uac-admin` (CLI),
   * `--icon=assets/favicon.ico`,
   * `--collect-all pydivert` so the bundled WinDivert driver (`.sys`)
     ships inside the exe,
   * `--collect-all pystray`, `--collect-all PIL` to cover plugin loaders
     that PyInstaller's static analysis can miss.
3. Invokes `ISCC.exe` (preinstalled on `windows-latest`) against
   `packaging/windows/whydpi.iss` to produce the setup exe.
4. Uploads all three files as release assets alongside the Linux
   `.deb`/`.rpm`.

## Local reproduction

From a Developer PowerShell with Python 3.11+ and Inno Setup 6 installed:

```powershell
# Set the version the installer stamps everywhere.
$env:WHYDPI_VERSION = "0.3.0"

# Build the two exes into packaging\windows\build\dist\
pyinstaller --onefile --windowed --uac-admin `
    --icon=..\..\assets\favicon.ico `
    --add-data "..\..\whydpi\ui\_assets;whydpi\ui\_assets" `
    --collect-all pydivert `
    --collect-all pystray `
    --collect-all PIL `
    --name whydpi-tray `
    --distpath build\dist `
    --workpath build\work `
    --specpath build `
    tray_entry.py

pyinstaller --onefile --console --uac-admin `
    --icon=..\..\assets\favicon.ico `
    --collect-all pydivert `
    --name whydpi `
    --distpath build\dist `
    --workpath build\work `
    --specpath build `
    cli_entry.py

# Produce the installer in packaging\windows\dist\
iscc whydpi.iss
```

The installer places everything under `%ProgramFiles%\whyDPI\` and
optionally registers a Task Scheduler entry for per-user autologon
(running as SYSTEM so no daily UAC prompt is needed).

## Debugging with `WHYDPI_TRACE=1`

Setting the `WHYDPI_TRACE` environment variable to `1` (or `true` /
`yes` / `on`) before starting the engine turns on per-packet logging
under the `whydpi.trace` logger.  Every intercepted event is emitted
at INFO so a standard `-v`-less run shows them:

| Event                                  | Example line                                                             |
|----------------------------------------|--------------------------------------------------------------------------|
| Outbound TCP/443 SYN                   | `tcp/443 SYN  10.0.0.5:51342 -> 1.2.3.4:443`                             |
| TLS ClientHello captured, with SNI     | `tcp/443 CHLO sni=example.com ... strategy=record:2 (cache=miss)`        |
| Fragment injection result              | `tcp/443 CHLO injected sni=example.com strategy=record:2 frags=2 delta=5B` |
| Inbound RST from server                | `tcp/443 RST  sni=example.com strategy=record:2 ... (DPI reset)`         |
| ServerHello observed                   | `tcp/443 ServerHello sni=example.com strategy=record:2 len=174B`         |
| Outbound QUIC packet + ICMP reject     | `udp/443 QUIC v4 10.0.0.5:51343 -> 1.2.3.4:443 len=1200B -> ICMP unreach`|
| DNS query parsed                       | `udp/53 query example.com A  10.0.0.5:55123 -> 8.8.8.8:53`               |
| DoH upstream result                    | `udp/53 DoH primary ok example.com A len=72B`                            |
| Synthetic reply injected               | `udp/53 reply injected 10.0.0.5 <- 8.8.8.8:53 len=72B`                   |

Typical debugging recipe for an app that hangs on startup
(Chromium/Electron desktop clients, game launchers, …):

```powershell
# Stop the installed service / tray, then in an elevated PowerShell:
Set-Location C:\path\to\whyDPI
$env:WHYDPI_TRACE = "1"
.\.venv\Scripts\python -m whydpi.cli start -v *>> diag\trace.log
```

Launch the misbehaving app in a second window; every TCP/443, UDP/443
and UDP/53 event it emits will be in `diag\trace.log` with a timestamp,
making it trivial to see whether it got DNS, whether its TLS handshake
survived, or whether its QUIC attempts are being rejected cleanly.

The flag has **zero cost** when unset (a single boolean check per
event), so leaving the code in production is safe.

## Why admin?

* **WinDivert** loads a kernel driver (`WinDivert64.sys`) — that requires
  `SeLoadDriverPrivilege`, which is an Administrator right.  Both the
  TLS-shaper handle (TCP/443) and the packet-layer DNS hijacker
  (`whydpi.system.dns_redirect_windows` — UDP/53) go through this same
  driver handle.
* **`DnsFlushResolverCache`** (Win32 API) is invoked once at startup to
  evict any ISP-poisoned entries the OS's built-in DNS client may have
  cached *before* whyDPI started.  Flushing the shared resolver cache
  is also an Administrator-only operation.

Unlike earlier versions, whyDPI 0.2.8+ does not run `netsh` or
install any NRPT rule — all DNS work is transient and lives at the
packet layer.  That means a crash, a kill -9 or a `systemctl stop`
leaves the OS's persistent DNS configuration **completely untouched**.

The installer embeds a UAC manifest so a plain double-click of
`whydpi-tray.exe` triggers the standard UAC consent prompt; the user
never needs to right-click → "Run as administrator".
