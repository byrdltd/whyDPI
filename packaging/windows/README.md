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
$env:WHYDPI_VERSION = "0.2.2"

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

## Why admin?

* **WinDivert** loads a kernel driver (`WinDivert64.sys`) — that requires
  `SeLoadDriverPrivilege`, which is an Administrator right.
* **`netsh interface ipv4 set dnsserver`** rewrites adapter DNS, which
  is an Administrator-only operation.

The installer embeds a UAC manifest so a plain double-click of
`whydpi-tray.exe` triggers the standard UAC consent prompt; the user
never needs to right-click → "Run as administrator".
