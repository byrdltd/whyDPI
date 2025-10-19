# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT
# For educational and research purposes only

"""
Packet injection module for whyDPI

Implements Random Garbage Fake Packet strategy for DPI bypass.
100% independent implementation - no external code dependencies.
"""

import logging
import os
from scapy.all import IP, TCP, Raw, send, conf
from .config import DEFAULT_TTL, FAKE_PACKET_SIZE

logger = logging.getLogger(__name__)


class PacketInjector:
    """
    Handles fake packet injection for DPI bypass.

    Strategy: Random Garbage Fake Packets
    -------------------------------------
    Instead of using pre-crafted packets or real packet fragments,
    we generate completely random garbage data for each fake packet.

    Why this works:
    1. DPI sees random garbage first → pattern matching fails
    2. Fake packet has low TTL (dies before reaching server)
    3. Real packet follows and passes through confused DPI
    4. Every packet is unique → DPI can't build signatures
    5. Simple, effective, 100% independent
    """

    def _detect_interface_with_retry(self, max_retries=5, retry_delay=1):
        """
        Detect network interface with retry logic for boot-time scenarios.

        Root cause of boot-time failure:
        - whydpi starts when NetworkManager says "startup complete"
        - But DHCP lease may still be in progress (takes ~2 more seconds)
        - Default route not yet configured (CONNECTED_LOCAL state)
        - scapy's conf.route.route() returns loopback

        Solution:
        - Retry with exponential backoff
        - Filter out loopback interface
        - Prefer interface with default route

        Args:
            max_retries (int): Maximum number of detection attempts
            retry_delay (float): Initial delay between retries (seconds)

        Returns:
            str: Network interface name (e.g., 'enp42s0') or None
        """
        import time
        import subprocess

        for attempt in range(max_retries):
            try:
                # Method 1: Try to get interface from default route (most reliable)
                result = subprocess.run(
                    ['ip', 'route', 'show', 'default'],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0 and result.stdout:
                    # Parse: "default via 192.168.1.1 dev enp42s0 ..."
                    parts = result.stdout.split()
                    if 'dev' in parts:
                        iface = parts[parts.index('dev') + 1]
                        logger.info(f"Detected interface from default route: {iface}")
                        return iface

                # Method 2: Use scapy but filter out loopback
                conf.route.resync()
                iface, _, _ = conf.route.route("8.8.8.8")
                if iface and iface != 'lo':
                    logger.info(f"Detected interface from scapy: {iface}")
                    return iface

                # Method 3: If loopback was selected, network isn't ready yet
                if iface == 'lo':
                    logger.warning(f"Attempt {attempt + 1}/{max_retries}: Network not ready (loopback selected), retrying in {retry_delay}s...")
                    time.sleep(retry_delay)
                    retry_delay *= 1.5  # Exponential backoff
                    continue

            except Exception as e:
                logger.warning(f"Attempt {attempt + 1}/{max_retries}: Interface detection failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    retry_delay *= 1.5
                    continue

        # Fallback: Let scapy try to find route at send time
        logger.error("Failed to detect network interface after retries, falling back to auto-detection")
        return None

    def __init__(self, ttl=DEFAULT_TTL, fake_size=FAKE_PACKET_SIZE):
        """
        Initialize packet injector.

        Args:
            ttl (int): Time-to-live for fake packets (default: 1)
            fake_size (int): Size of random garbage to inject (default: 500)
        """
        # Detect network interface with boot-time retry logic
        # Problem: At boot, DHCP may not be complete yet, causing loopback selection
        # Solution: Retry with backoff, filter out loopback, prefer default route
        self.iface = self._detect_interface_with_retry()

        self.ttl = ttl
        self.fake_size = fake_size
        self.stats = {
            'injected': 0,
            'errors': 0
        }

        if self.iface:
            logger.info(f"PacketInjector initialized: interface={self.iface}, TTL={ttl}, fake_size={fake_size} bytes")
        else:
            logger.warning(f"PacketInjector initialized without interface (auto-detection mode), TTL={ttl}, fake_size={fake_size} bytes")

    def inject_random_garbage(self, src_ip, dst_ip, src_port, dst_port, seq):
        """
        Inject random garbage fake packet.

        This is our DPI bypass strategy. We send completely random data
        with low TTL that confuses DPI but never reaches the server.

        Strategy:
        1. Generate random bytes (os.urandom - cryptographically secure)
        2. Send with WRONG SEQ (server will reject if it arrives)
        3. Send with LOW TTL (expires before reaching server)
        4. DPI sees garbage → gets confused
        5. Real packet passes through confused DPI

        Args:
            src_ip (str): Source IP address
            dst_ip (str): Destination IP address
            src_port (int): Source TCP port
            dst_port (int): Destination TCP port
            seq (int): TCP sequence number (from REAL packet)

        Returns:
            bool: True if injection successful, False otherwise
        """
        try:
            # Generate cryptographically secure random garbage
            random_garbage = os.urandom(self.fake_size)

            # Use SAME SEQ number as real packet
            # Server will see duplicate packets and ignore fake (garbage)
            # But DPI will see fake first and get confused
            fake_seq = seq  # SAME as real packet

            # Craft fake packet with random garbage
            fake_packet = IP(
                src=src_ip,
                dst=dst_ip,
                ttl=self.ttl  # Dies after N hops
            ) / TCP(
                sport=src_port,
                dport=dst_port,
                seq=fake_seq,  # WRONG SEQ NUMBER
                flags='PA'  # PSH+ACK
            ) / Raw(load=random_garbage)

            # Send via raw socket (requires root)
            # Note: For Layer 3 (IP) packets, Scapy uses routing table automatically
            # The conf.route.route() call in __init__ ensures routing table is loaded
            send(fake_packet, verbose=0)

            self.stats['injected'] += 1
            logger.debug(
                f"Injected random garbage: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, "
                f"size={self.fake_size}, TTL={self.ttl}, fake_SEQ={fake_seq}, real_SEQ={seq}"
            )
            return True

        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"Failed to inject fake packet: {e}")
            return False

    def get_stats(self):
        """Get injection statistics."""
        return self.stats.copy()
