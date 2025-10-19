# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT
# For educational and research purposes only

"""
DNS configuration module for whyDPI

Handles DNS bypass configuration (Yandex DNS).
"""

import logging
import os
import subprocess
from .config import YANDEX_DNS_PRIMARY, YANDEX_DNS_SECONDARY

logger = logging.getLogger(__name__)


class DNSConfig:
    """
    Handles DNS configuration for DPI bypass.

    Configures system to use Yandex DNS to avoid DNS hijacking.
    """

    RESOLV_CONF_PATH = "/etc/resolv.conf"
    RESOLV_CONF_BACKUP = "/etc/resolv.conf.whyDPI.backup"

    @staticmethod
    def is_configured():
        """
        Check if Yandex DNS is already configured.

        Returns:
            bool: True if configured, False otherwise
        """
        try:
            if not os.path.exists(DNSConfig.RESOLV_CONF_PATH):
                return False

            with open(DNSConfig.RESOLV_CONF_PATH, 'r') as f:
                content = f.read()
                return YANDEX_DNS_PRIMARY in content

        except Exception as e:
            logger.error(f"Failed to check DNS configuration: {e}")
            return False

    @staticmethod
    def _get_active_nm_connections():
        """
        Get active NetworkManager connection names.

        Returns:
            list: List of active connection names
        """
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'NAME,TYPE', 'connection', 'show', '--active'],
                capture_output=True,
                text=True,
                check=False
            )
            if result.returncode != 0:
                return []

            connections = []
            for line in result.stdout.strip().split('\n'):
                if line and ':' in line:
                    name, conn_type = line.split(':', 1)
                    # Only configure ethernet and wifi connections
                    if conn_type in ['802-3-ethernet', '802-11-wireless', 'ethernet', 'wifi']:
                        connections.append(name)
            return connections
        except:
            return []

    @staticmethod
    def configure():
        """
        Configure Yandex DNS.

        Backs up current resolv.conf and sets Yandex DNS.
        Also configures NetworkManager to use Yandex DNS.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Backup current resolv.conf (only if it's a real file, not a symlink)
            if os.path.exists(DNSConfig.RESOLV_CONF_PATH):
                if os.path.islink(DNSConfig.RESOLV_CONF_PATH):
                    logger.info(f"{DNSConfig.RESOLV_CONF_PATH} is a symlink, backing up target")
                    # Backup the symlink target
                    real_path = os.path.realpath(DNSConfig.RESOLV_CONF_PATH)
                    subprocess.run(
                        ['cp', real_path, DNSConfig.RESOLV_CONF_BACKUP],
                        check=True,
                        capture_output=True
                    )
                else:
                    logger.info(f"Backing up {DNSConfig.RESOLV_CONF_PATH}")
                    subprocess.run(
                        ['cp', DNSConfig.RESOLV_CONF_PATH, DNSConfig.RESOLV_CONF_BACKUP],
                        check=True,
                        capture_output=True
                    )

            # Disable systemd-resolved if running (stop + disable + mask)
            try:
                result = subprocess.run(
                    ['systemctl', 'is-active', 'systemd-resolved'],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    logger.info("Stopping and masking systemd-resolved")
                    subprocess.run(['systemctl', 'stop', 'systemd-resolved'], check=False)
                    subprocess.run(['systemctl', 'disable', 'systemd-resolved'], check=False)
                    subprocess.run(['systemctl', 'mask', 'systemd-resolved'], check=False)
            except Exception as e:
                logger.debug(f"systemd-resolved check/disable failed (may not exist): {e}")

            # Remove immutable flag if set
            try:
                subprocess.run(
                    ['chattr', '-i', DNSConfig.RESOLV_CONF_PATH],
                    check=False,
                    capture_output=True,
                    stderr=subprocess.DEVNULL
                )
            except:
                pass

            # Remove /etc/resolv.conf if it's a symlink
            if os.path.islink(DNSConfig.RESOLV_CONF_PATH):
                logger.info(f"Removing symlink {DNSConfig.RESOLV_CONF_PATH}")
                os.remove(DNSConfig.RESOLV_CONF_PATH)

            # Write new resolv.conf
            dns_config = f"""# Yandex DNS configured by whyDPI
# Backup saved to {DNSConfig.RESOLV_CONF_BACKUP}
nameserver {YANDEX_DNS_PRIMARY}
nameserver {YANDEX_DNS_SECONDARY}
"""
            with open(DNSConfig.RESOLV_CONF_PATH, 'w') as f:
                f.write(dns_config)

            # Make immutable to prevent NetworkManager from overwriting
            try:
                subprocess.run(
                    ['chattr', '+i', DNSConfig.RESOLV_CONF_PATH],
                    check=True,
                    capture_output=True
                )
                logger.info(f"Made {DNSConfig.RESOLV_CONF_PATH} immutable")
            except Exception as e:
                logger.warning(f"Failed to make resolv.conf immutable: {e}")

            # Configure NetworkManager connections to use Yandex DNS
            connections = DNSConfig._get_active_nm_connections()
            if connections:
                logger.info(f"Configuring NetworkManager connections: {connections}")
                dns_servers = f"{YANDEX_DNS_PRIMARY},{YANDEX_DNS_SECONDARY}"
                for conn in connections:
                    try:
                        # Set DNS servers
                        subprocess.run(
                            ['nmcli', 'connection', 'modify', conn, 'ipv4.dns', dns_servers],
                            check=False,
                            capture_output=True
                        )
                        # Ignore auto DNS from DHCP
                        subprocess.run(
                            ['nmcli', 'connection', 'modify', conn, 'ipv4.ignore-auto-dns', 'yes'],
                            check=False,
                            capture_output=True
                        )
                        # Reload connection
                        subprocess.run(
                            ['nmcli', 'connection', 'up', conn],
                            check=False,
                            capture_output=True
                        )
                        logger.info(f"Configured NetworkManager connection: {conn}")
                    except Exception as e:
                        logger.warning(f"Failed to configure NetworkManager connection {conn}: {e}")

            logger.info("DNS configured successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to configure DNS: {e}")
            return False

    @staticmethod
    def restore():
        """
        Restore original DNS configuration.
        Also restores NetworkManager DNS settings.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Remove immutable flag
            try:
                subprocess.run(
                    ['chattr', '-i', DNSConfig.RESOLV_CONF_PATH],
                    check=False,
                    capture_output=True,
                    stderr=subprocess.DEVNULL
                )
            except:
                pass

            # Restore backup if exists
            if os.path.exists(DNSConfig.RESOLV_CONF_BACKUP):
                logger.info(f"Restoring {DNSConfig.RESOLV_CONF_BACKUP}")
                subprocess.run(
                    ['cp', DNSConfig.RESOLV_CONF_BACKUP, DNSConfig.RESOLV_CONF_PATH],
                    check=True,
                    capture_output=True
                )
                os.remove(DNSConfig.RESOLV_CONF_BACKUP)

            # Restore NetworkManager DNS settings
            connections = DNSConfig._get_active_nm_connections()
            if connections:
                logger.info(f"Restoring NetworkManager DNS for connections: {connections}")
                for conn in connections:
                    try:
                        # Clear manual DNS servers
                        subprocess.run(
                            ['nmcli', 'connection', 'modify', conn, 'ipv4.dns', ''],
                            check=False,
                            capture_output=True
                        )
                        # Re-enable auto DNS from DHCP
                        subprocess.run(
                            ['nmcli', 'connection', 'modify', conn, 'ipv4.ignore-auto-dns', 'no'],
                            check=False,
                            capture_output=True
                        )
                        # Reload connection
                        subprocess.run(
                            ['nmcli', 'connection', 'up', conn],
                            check=False,
                            capture_output=True
                        )
                        logger.info(f"Restored NetworkManager connection: {conn}")
                    except Exception as e:
                        logger.warning(f"Failed to restore NetworkManager connection {conn}: {e}")

            # Re-enable systemd-resolved (unmask + enable + start)
            try:
                subprocess.run(['systemctl', 'unmask', 'systemd-resolved'], check=False)
                subprocess.run(['systemctl', 'enable', 'systemd-resolved'], check=False)
                subprocess.run(['systemctl', 'start', 'systemd-resolved'], check=False)
            except:
                pass

            logger.info("DNS configuration restored")
            return True

        except Exception as e:
            logger.error(f"Failed to restore DNS: {e}")
            return False
