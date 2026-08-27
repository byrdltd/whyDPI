# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Windows in-app updates against GitHub Releases.

The tray may *check* ``releases/latest`` on a schedule.  The installer
payload is downloaded only after the user confirms — this is not a
silent auto-update channel.

Linux is out of scope: distro packages (AUR / apt / dnf) are the
update path there.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from ..i18n import t

logger = logging.getLogger(__name__)

GITHUB_REPO = "byrdltd/whyDPI"
LATEST_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
USER_AGENT = "whyDPI-update-check"
CHECK_INTERVAL_S = 24 * 3600
_SETUP_NAME_RE = re.compile(r"^whydpi-.+-setup\.exe$", re.IGNORECASE)

Fetcher = Callable[[str], bytes]


@dataclass(frozen=True)
class UpdateInfo:
    version: str
    tag: str
    html_url: str
    setup_url: str | None
    setup_name: str | None
    sha256sums_url: str | None


def parse_version(raw: str) -> tuple[int, ...]:
    """Best-effort numeric tuple from a tag or ``__version__`` string."""
    s = raw.strip().lstrip("vV")
    nums: list[int] = []
    for part in s.split("."):
        digits = ""
        for ch in part:
            if ch.isdigit():
                digits += ch
            else:
                break
        nums.append(int(digits) if digits else 0)
    return tuple(nums) or (0,)


def is_newer(remote: str, local: str) -> bool:
    return parse_version(remote) > parse_version(local)


def detect_channel(
    exe_path: str | None = None,
    environ: dict[str, str] | None = None,
) -> str:
    """Return ``scoop``, ``inno``, or ``portable`` from the running path."""
    env = environ if environ is not None else os.environ
    path = exe_path
    if not path:
        path = sys.executable if getattr(sys, "frozen", False) else (sys.argv[0] or "")

    def _norm(p: str) -> str:
        return os.path.normpath(p).replace("\\", "/").lower()

    lowered = _norm(path)
    if "scoop/apps/whydpi" in lowered:
        return "scoop"
    for key in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        root = env.get(key)
        if not root:
            continue
        prefix = _norm(os.path.join(root, "whyDPI"))
        if lowered == prefix or lowered.startswith(prefix + "/"):
            return "inno"
    return "portable"


def cache_path(environ: dict[str, str] | None = None) -> Path:
    env = environ if environ is not None else os.environ
    if sys.platform == "win32":
        base = env.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "whyDPI" / "update-check.json"
    xdg = env.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(xdg) / "whydpi" / "update-check.json"


def _http_get(url: str, timeout: float = 20.0) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return resp.read()


def select_setup_asset(
    assets: list[dict],
    version: str,
) -> tuple[str | None, str | None, str | None]:
    """Pick ``setup.exe`` + optional SHA256SUMS URLs from a release asset list.

    Returns ``(setup_url, setup_name, sha256sums_url)``.
    """
    setup_url = setup_name = sums_url = None
    preferred = f"whydpi-{version}-setup.exe".lower()
    for asset in assets:
        name = str(asset.get("name") or "")
        url = str(asset.get("browser_download_url") or "")
        if not name or not url:
            continue
        lower = name.lower()
        if lower == "sha256sums.txt" or lower == "sha256sums":
            sums_url = url
            continue
        if lower == preferred:
            setup_url, setup_name = url, name
            continue
        if setup_url is None and _SETUP_NAME_RE.match(name):
            setup_url, setup_name = url, name
    return setup_url, setup_name, sums_url


def parse_latest_payload(payload: dict) -> UpdateInfo | None:
    tag = str(payload.get("tag_name") or "").strip()
    if not tag:
        return None
    version = tag.lstrip("vV")
    assets = payload.get("assets") or []
    if not isinstance(assets, list):
        assets = []
    setup_url, setup_name, sums_url = select_setup_asset(assets, version)
    return UpdateInfo(
        version=version,
        tag=tag,
        html_url=str(payload.get("html_url") or ""),
        setup_url=setup_url,
        setup_name=setup_name,
        sha256sums_url=sums_url,
    )


def _info_from_cache(data: dict) -> UpdateInfo:
    return UpdateInfo(
        version=str(data.get("version") or ""),
        tag=str(data.get("tag") or ""),
        html_url=str(data.get("html_url") or ""),
        setup_url=data.get("setup_url"),
        setup_name=data.get("setup_name"),
        sha256sums_url=data.get("sha256sums_url"),
    )


def _read_cache(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_cache(path: Path, info: UpdateInfo, checked_at: float, current: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = asdict(info)
    blob["checked_at"] = checked_at
    blob["current_at_check"] = current
    path.write_text(json.dumps(blob, indent=2) + "\n", encoding="utf-8")


def check_for_update(
    current_version: str,
    *,
    now: float | None = None,
    fetcher: Fetcher | None = None,
    cache_file: Path | None = None,
    force: bool = False,
) -> UpdateInfo | None:
    """Return remote :class:`UpdateInfo` when it is newer than *current_version*.

    Network and parse failures are swallowed (logged) and return ``None``.
    """
    ts = time.time() if now is None else now
    path = cache_file or cache_path()
    cached = _read_cache(path)
    if (
        not force
        and cached
        and (ts - float(cached.get("checked_at") or 0)) < CHECK_INTERVAL_S
        and str(cached.get("current_at_check") or "") == current_version
    ):
        info = _info_from_cache(cached)
        if info.version and is_newer(info.version, current_version):
            return info
        return None

    get = fetcher or _http_get
    try:
        raw = get(LATEST_URL)
        payload = json.loads(raw.decode("utf-8"))
    except (
        OSError,
        urllib.error.URLError,
        json.JSONDecodeError,
        UnicodeDecodeError,
        ValueError,
    ) as exc:
        logger.info("update: latest-release check failed: %s", exc)
        return None
    if not isinstance(payload, dict):
        return None
    info = parse_latest_payload(payload)
    if info is None:
        return None
    try:
        _write_cache(path, info, ts, current_version)
    except OSError as exc:
        logger.debug("update: could not write cache: %s", exc)
    if is_newer(info.version, current_version):
        return info
    return None


def parse_sha256sums(text: str, filename: str) -> str | None:
    want = filename.strip().lower()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        listed = parts[-1].lstrip("*").replace("\\", "/").split("/")[-1].lower()
        if listed == want:
            return parts[0].lower()
    return None


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download_setup(
    info: UpdateInfo,
    dest_dir: Path,
    *,
    fetcher: Fetcher | None = None,
) -> Path:
    """Download ``setup.exe`` into *dest_dir* and verify SHA256 when published."""
    if not info.setup_url or not info.setup_name:
        raise RuntimeError(t("update.error.no_asset"))
    get = fetcher or _http_get
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / info.setup_name
    dest.write_bytes(get(info.setup_url))
    if info.sha256sums_url:
        sums = get(info.sha256sums_url).decode("utf-8", errors="replace")
        expected = parse_sha256sums(sums, info.setup_name)
        if expected is None:
            raise RuntimeError(t("update.error.no_sha", name=info.setup_name))
        actual = _sha256_file(dest)
        if actual != expected:
            try:
                dest.unlink()
            except OSError:
                pass
            raise RuntimeError(
                t("update.error.hash", expected=expected, actual=actual)
            )
    return dest


def _spawn_scoop_update() -> None:
    scoop = shutil.which("scoop") or shutil.which("scoop.cmd")
    if not scoop:
        raise RuntimeError(t("update.error.no_scoop"))
    # Delay so the tray process can release file locks before Scoop replaces it.
    cmd = f'timeout /t 2 /nobreak >nul & "{scoop}" update whydpi'
    flags = 0
    if sys.platform == "win32":
        flags = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    subprocess.Popen(  # noqa: S602
        cmd,
        shell=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=flags,
    )


def launch_installer(setup_path: Path) -> None:
    if sys.platform == "win32":
        os.startfile(str(setup_path))  # type: ignore[attr-defined]
        return
    subprocess.Popen([str(setup_path)])


def apply_update(
    info: UpdateInfo,
    *,
    channel: str | None = None,
    fetcher: Fetcher | None = None,
    dest_dir: Path | None = None,
) -> bool:
    """Start the channel-appropriate updater.

    Returns ``True`` when the caller should quit the tray so files can
    be replaced.  Raises on failure (caller shows a toast).
    """
    ch = channel or detect_channel()
    if ch == "scoop":
        _spawn_scoop_update()
        return True
    dest = dest_dir or Path(tempfile.gettempdir()) / "whyDPI-update"
    setup = download_setup(info, dest, fetcher=fetcher)
    launch_installer(setup)
    return True
