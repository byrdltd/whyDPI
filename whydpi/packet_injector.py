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

    def __init__(self, ttl=DEFAULT_TTL, fake_size=FAKE_PACKET_SIZE):
        """
        Initialize packet injector.

        Args:
            ttl (int): Time-to-live for fake packets (default: 1)
            fake_size (int): Size of random garbage to inject (default: 500)
        """
        # Force reload routing table to avoid boot-time race condition
        # This ensures scapy has fresh routing info even if started early in boot
        try:
            conf.route.resync()
            logger.debug("Scapy routing table resynced successfully")
        except Exception as e:
            logger.warning(f"Failed to resync routing table: {e}")

        # Trigger route resolution to ensure routing table is properly loaded
        # This avoids "no route found" errors during packet injection
        # We don't actually use the interface value, just force route initialization
        try:
            iface, _, _ = conf.route.route("8.8.8.8")
            logger.debug(f"Routing table loaded successfully (interface: {iface})")
        except Exception as e:
            logger.warning(f"Failed to load routing table: {e}")

        self.ttl = ttl
        self.fake_size = fake_size
        self.stats = {
            'injected': 0,
            'errors': 0
        }
        logger.info(f"PacketInjector initialized: TTL={ttl}, fake_size={fake_size} bytes (random garbage)")

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
