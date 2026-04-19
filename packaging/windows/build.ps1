# Local Windows installer build — mirrors .github/workflows/release.yml.
# Usage (from repo root):
#   $env:WHYDPI_VERSION = "0.3.0"
#   .\packaging\windows\build.ps1
#
# Produces:
#   packaging\windows\build\dist\whydpi-tray\whydpi-tray.exe + _internal\
#   packaging\windows\build\dist\whydpi\whydpi.exe + _internal\
#   packaging\windows\dist\whydpi-<ver>-setup.exe
#
# We build both exes in ``--onedir`` rather than ``--onefile`` mode:
# WinDivert keeps its kernel driver file mapped after the userspace
# handle is closed, which makes the onefile bootloader's ``_MEI*``
# temp-directory cleanup race the driver and lose — surfacing as a
# "Failed to remove temporary directory" popup every time the tray
# exits.  Shipping the runtime alongside the exe inside
# ``{app}\_internal\`` eliminates the temp extraction entirely, so
# the popup can't happen.
#
# Keeps its own .venv-build at the repo root so we don't pollute the
# developer's interpreter, and so repeated runs reuse pip cache for
# speed.
param(
    [string]$Version = $env:WHYDPI_VERSION,
    [switch]$SkipVenv
)

# Do NOT set ErrorActionPreference=Stop: PyInstaller prints normal
# progress to stderr and Windows PowerShell 5.1 (which is what the
# dev box here runs) lifts every stderr line into an error record that
# aborts the script.  We guard every native invocation with an
# explicit $LASTEXITCODE check instead, which is both more portable
# and produces clearer failure logs.
$ErrorActionPreference = 'Continue'

if ([string]::IsNullOrWhiteSpace($Version)) {
    $pyproject = Join-Path $PSScriptRoot '..\..\pyproject.toml'
    $line = Get-Content $pyproject | Where-Object { $_ -match '^version\s*=\s*"([^"]+)"' } | Select-Object -First 1
    if ($line -and $line -match '"([^"]+)"') { $Version = $matches[1] }
    if ([string]::IsNullOrWhiteSpace($Version)) { $Version = '0.0.0' }
}

$env:WHYDPI_VERSION = $Version
Write-Host "=== whyDPI local Windows build ==="
Write-Host "version: $Version"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$repoRoot = $repoRoot.Path
Write-Host "repo   : $repoRoot"

Push-Location $repoRoot
try {
    $venv = Join-Path $repoRoot '.venv-build'
    if (-not $SkipVenv -and -not (Test-Path $venv)) {
        Write-Host "creating build venv at $venv"
        $sys_py = (Get-Command python -ErrorAction SilentlyContinue).Source
        if (-not $sys_py) { $sys_py = (Get-Command py -ErrorAction SilentlyContinue).Source }
        if (-not $sys_py) { throw "python not found on PATH" }
        & $sys_py -m venv $venv
    }
    $py = Join-Path $venv 'Scripts\python.exe'
    if (-not (Test-Path $py)) { throw "build venv python missing: $py" }

    Write-Host "=== installing build deps ==="
    & $py -m pip install --upgrade pip
    & $py -m pip install ".[windows]"
    & $py -m pip install pyinstaller

    Write-Host "=== diagnostics ==="
    & $py --version
    & $py -c "from whydpi.ui.tray import run; print('tray import ok')"
    & $py -c "from whydpi.platforms import windows; print('platforms.windows import ok')"
    & $py -c "from whydpi.system import windivert, dns_redirect_windows; print('system modules import ok')"

    # Build both exes from packaging/windows/ so PyInstaller picks up
    # tray_entry.py / cli_entry.py without absolute path juggling.
    Push-Location (Join-Path $repoRoot 'packaging\windows')
    try {
        $buildDir = Join-Path (Get-Location) 'build'
        if (Test-Path $buildDir) { Remove-Item -Recurse -Force $buildDir }
        New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
        $distSetup = Join-Path (Get-Location) 'dist'
        if (Test-Path $distSetup) { Remove-Item -Recurse -Force $distSetup }

        $assets = Join-Path $repoRoot 'whydpi\ui\_assets'
        $icon   = Join-Path $repoRoot 'assets\favicon.ico'

        Write-Host "=== build whydpi-tray (onedir) ==="
        & $py -m PyInstaller --onedir --windowed --uac-admin `
            --log-level=INFO `
            --icon="$icon" `
            --add-data "${assets};whydpi/ui/_assets" `
            --collect-all whydpi `
            --collect-all pydivert `
            --collect-all pystray `
            --collect-all PIL `
            --copy-metadata whydpi `
            --hidden-import whydpi.platforms.windows `
            --hidden-import whydpi.system.windivert `
            --hidden-import whydpi.system.dns_redirect_windows `
            --hidden-import whydpi.system._trace `
            --hidden-import whydpi.net.dns `
            --hidden-import whydpi.net.dns_cache `
            --hidden-import whydpi.ui.tray `
            --hidden-import whydpi.ui.autostart `
            --hidden-import whydpi.ui.consent `
            --hidden-import whydpi.ui.status_window `
            --name whydpi-tray `
            --distpath build\dist `
            --workpath build\work `
            --specpath build `
            tray_entry.py 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "pyinstaller tray failed (exit $LASTEXITCODE)" }

        Write-Host "=== build whydpi (onedir) ==="
        # The CLI exe is a second onedir build that lives in its own
        # ``cli\`` subfolder so its ``_internal\`` runtime cannot
        # collide with the tray's.  Power users invoke it directly
        # (``"C:\Program Files\whyDPI\cli\whydpi.exe" status``); the
        # installer wires up a Start-menu shortcut to the same path.
        & $py -m PyInstaller --onedir --console --uac-admin `
            --log-level=INFO `
            --icon="$icon" `
            --collect-all whydpi `
            --collect-all pydivert `
            --copy-metadata whydpi `
            --hidden-import whydpi.platforms.windows `
            --hidden-import whydpi.system.windivert `
            --hidden-import whydpi.system.dns_redirect_windows `
            --hidden-import whydpi.system._trace `
            --hidden-import whydpi.net.dns `
            --hidden-import whydpi.net.dns_cache `
            --hidden-import whydpi.cli `
            --name whydpi `
            --distpath build\dist-cli `
            --workpath build\work `
            --specpath build `
            cli_entry.py 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "pyinstaller cli failed (exit $LASTEXITCODE)" }

        Write-Host "=== compile Inno Setup installer ==="
        # Hunt for ISCC.exe in every install layout we have seen in the
        # wild: system-wide under Program Files (x86), per-user under
        # %LOCALAPPDATA%\Programs, and any side-by-side ``Inno Setup *``
        # install.  We don't fail the build if none are present; we
        # just skip and leave the two exes for manual packaging.
        $isccCandidates = @(
            "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
            "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
            "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
        )
        $iscc = $isccCandidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
        if (-not $iscc) {
            foreach ($root in @("${env:ProgramFiles(x86)}", "$env:ProgramFiles", "$env:LOCALAPPDATA\Programs")) {
                if (-not $root) { continue }
                $hit = Get-ChildItem $root -Filter "ISCC.exe" -Recurse -ErrorAction SilentlyContinue -Depth 3 | Select-Object -First 1
                if ($hit) { $iscc = $hit.FullName; break }
            }
        }
        if (-not $iscc) { throw "Inno Setup ISCC.exe not found in Program Files or %LOCALAPPDATA%\Programs" }
        Write-Host "using ISCC: $iscc"
        & "$iscc" /V9 whydpi.iss 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed (exit $LASTEXITCODE)" }

        Write-Host "=== build artefacts ==="
        Write-Host "tray onedir:"
        Get-ChildItem build\dist\whydpi-tray | Format-Table Name,Length,LastWriteTime
        Write-Host "cli onedir:"
        Get-ChildItem build\dist-cli\whydpi | Format-Table Name,Length,LastWriteTime
        Write-Host "installer:"
        Get-ChildItem dist | Format-Table Name,Length,LastWriteTime
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "=== DONE ==="
Write-Host "installer: packaging\windows\dist\whydpi-$Version-setup.exe"
