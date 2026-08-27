# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""System resolver configuration.

Points ``/etc/resolv.conf`` at our local stub (DoH) or at an explicit upstream,
and asks NetworkManager not to overwrite it.  The previous DNS state is backed
up and fully restored on :func:`restore`.

Design notes
------------

* We *never* mask ``systemd-resolved``: stopping it is enough for as long as
  whyDPI is running, and unmask/enable on shutdown keeps the original system
  layout intact.
* The backup is validated before it is restored.  If a previous crash left a
  ``whyDPI managed`` resolv.conf as the "backup", we discard it and ask
  NetworkManager to regenerate the default resolv.conf from scratch.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path


logger = logging.getLogger(__name__)

RESOLV_CONF = Path("/etc/resolv.conf")
RESOLV_BACKUP = Path("/etc/resolv.conf.whyDPI.backup")
RESOLV_OPTIONS = "options timeout:1 attempts:1 rotate single-request-reopen"

MANAGED_MARKER = "# whyDPI managed resolver"


def _active_nm_connections() -> list[str]:
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show", "--active"],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        return []
    if result.returncode != 0:
        return []
    names: list[str] = []
    for line in result.stdout.strip().splitlines():
        if ":" not in line:
            continue
        name, ctype = line.split(":", 1)
        if ctype in ("802-3-ethernet", "802-11-wireless", "ethernet", "wifi"):
            names.append(name)
    return names


def _stop_systemd_resolved() -> None:
    try:
        status = subprocess.run(
            ["systemctl", "is-active", "systemd-resolved"],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        return
    if status.returncode == 0:
        logger.info("Stopping systemd-resolved")
        subprocess.run(
            ["systemctl", "stop", "systemd-resolved"],
            check=False, capture_output=True,
        )


def _start_systemd_resolved_if_available() -> None:
    try:
        status = subprocess.run(
            ["systemctl", "is-enabled", "systemd-resolved"],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        return
    if status.returncode == 0 and status.stdout.strip() in ("enabled", "enabled-runtime"):
        subprocess.run(
            ["systemctl", "start", "systemd-resolved"],
            check=False, capture_output=True,
        )


def _chattr(flag: str) -> None:
    subprocess.run(["chattr", flag, str(RESOLV_CONF)],
                   check=False, capture_output=True)


def _resolv_is_managed(path: Path) -> bool:
    try:
        return path.exists() and path.read_text(errors="replace").startswith(MANAGED_MARKER)
    except OSError:
        return False


def is_configured(servers: list[str]) -> bool:
    try:
        if not RESOLV_CONF.exists():
            return False
        text = RESOLV_CONF.read_text()
        return all(s in text for s in servers) and RESOLV_OPTIONS in text
    except OSError:
        return False


def configure(servers: list[str]) -> bool:
    """Pin ``/etc/resolv.conf`` to *servers* and silence NetworkManager."""
    try:
        # Only take a backup if we have a real, non-managed resolv.conf.  This
        # protects us from overwriting a good backup with our own stub file
        # when ``configure`` is called repeatedly without an intervening
        # ``restore`` (e.g. after a crash).
        if (
            RESOLV_CONF.exists()
            and not RESOLV_BACKUP.exists()
            and not _resolv_is_managed(RESOLV_CONF)
        ):
            target = RESOLV_CONF.resolve() if RESOLV_CONF.is_symlink() else RESOLV_CONF
            subprocess.run(["cp", str(target), str(RESOLV_BACKUP)],
                           check=True, capture_output=True)
            logger.info("Backed up %s", RESOLV_CONF)

        _stop_systemd_resolved()
        _chattr("-i")

        if RESOLV_CONF.is_symlink():
            RESOLV_CONF.unlink()

        with RESOLV_CONF.open("w") as fh:
            fh.write(MANAGED_MARKER + "\n")
            for s in servers:
                fh.write(f"nameserver {s}\n")
            fh.write(RESOLV_OPTIONS + "\n")

        _chattr("+i")

        for conn in _active_nm_connections():
            subprocess.run(
                ["nmcli", "connection", "modify", conn,
                 "ipv4.dns", ",".join(servers),
                 "ipv4.dns-options", "timeout:1 attempts:1 rotate",
                 "ipv4.ignore-auto-dns", "yes",
                 "ipv6.dns", "",
                 "ipv6.ignore-auto-dns", "yes"],
                check=False, capture_output=True,
            )
            subprocess.run(["nmcli", "connection", "up", conn],
                           check=False, capture_output=True)

        logger.info("DNS resolver pinned to %s", ", ".join(servers))
        return True
    except Exception as exc:
        logger.error("DNS configure failed: %s", exc)
        return False


def restore() -> bool:
    try:
        _chattr("-i")

        restored_from_backup = False
        if RESOLV_BACKUP.exists():
            if _resolv_is_managed(RESOLV_BACKUP):
                logger.warning(
                    "Backup contains whyDPI marker — discarding as invalid"
                )
                RESOLV_BACKUP.unlink()
            else:
                subprocess.run(["cp", str(RESOLV_BACKUP), str(RESOLV_CONF)],
                               check=True, capture_output=True)
                RESOLV_BACKUP.unlink()
                logger.info("Restored /etc/resolv.conf from backup")
                restored_from_backup = True

        # Hand control back to NetworkManager and systemd-resolved (if the
        # distro uses them).  When no backup exists we let NM regenerate
        # resolv.conf from scratch by clearing the DNS overrides we pushed.
        for conn in _active_nm_connections():
            subprocess.run(
                ["nmcli", "connection", "modify", conn,
                 "ipv4.dns", "",
                 "ipv4.ignore-auto-dns", "no",
                 "ipv6.dns", "",
                 "ipv6.ignore-auto-dns", "no"],
                check=False, capture_output=True,
            )
            subprocess.run(["nmcli", "connection", "up", conn],
                           check=False, capture_output=True)

        # We never *disabled* systemd-resolved, only stopped it.  Start it
        # again if it is still enabled.  (``unmask`` is a no-op when not
        # masked — safe to call either way, and kept as a self-heal step for
        # users migrating from older whyDPI versions.)
        subprocess.run(["systemctl", "unmask", "systemd-resolved"],
                       check=False, capture_output=True)
        _start_systemd_resolved_if_available()

        # If we didn't restore anything and resolv.conf is still our managed
        # file (e.g. we were a symlink victim), point it back at the stub
        # symlink used by systemd-resolved as a sensible default.
        if not restored_from_backup and _resolv_is_managed(RESOLV_CONF):
            try:
                RESOLV_CONF.unlink()
                stub = Path("/run/systemd/resolve/stub-resolv.conf")
                if stub.exists():
                    RESOLV_CONF.symlink_to(stub)
                    logger.info("resolv.conf symlinked back to systemd-resolved stub")
            except OSError as exc:
                logger.warning("Could not restore resolv.conf symlink: %s", exc)

        return True
    except Exception as exc:
        logger.error("DNS restore failed: %s", exc)
        return False
