"""
NFQUEUE handler module for whyDPI

Handles packet interception via Linux NFQUEUE and triggers fake injection.
"""

import logging
import struct
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP
from .packet_injector import PacketInjector
from .config import DEFAULT_QUEUE_NUM, DEFAULT_PORTS

logger = logging.getLogger(__name__)


class NFQueueHandler:
    """
    Handles packet interception and DPI bypass via NFQUEUE.

    Intercepts packets matched by iptables NFQUEUE rule,
    injects fake packets, and releases real packets.
    """

    def __init__(self, queue_num=DEFAULT_QUEUE_NUM, ttl=3, ports=None):
        """
        Initialize NFQUEUE handler.

        Args:
            queue_num (int): NFQUEUE number (must match iptables rule)
            ttl (int): TTL for fake packets
            ports (list): List of ports to intercept (default: [80, 443])
        """
        self.queue_num = queue_num
        self.ports = ports or DEFAULT_PORTS
        self.injector = PacketInjector(ttl=ttl)
        self.nfqueue = None
        self.stats = {
            'processed': 0,
            'bypassed': 0,
            'accepted': 0
        }
        logger.info(f"NFQueueHandler initialized: queue={queue_num}, ttl={ttl}, ports={ports}")

    def _parse_packet(self, packet_data):
        """
        Parse packet data using scapy.

        Args:
            packet_data (bytes): Raw packet data

        Returns:
            scapy.packet or None
        """
        try:
            return IP(packet_data)
        except Exception as e:
            logger.debug(f"Failed to parse packet: {e}")
            return None

    def _should_bypass(self, pkt):
        """
        Determine if packet should trigger DPI bypass.

        Args:
            pkt: Scapy packet object

        Returns:
            bool: True if should bypass, False otherwise
        """
        # Must have IP and TCP layers
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return False

        tcp = pkt[TCP]

        # Check if destination port is in our list
        if tcp.dport not in self.ports:
            return False

        # Only process packets with data (PSH flag or payload)
        if not tcp.payload or len(bytes(tcp.payload)) == 0:
            return False

        # Check for TLS ClientHello (port 443)
        if tcp.dport == 443:
            payload = bytes(tcp.payload)
            # TLS record starts with 0x16 (Handshake)
            # Followed by version (0x03 0x01, 0x03 0x03, etc.)
            if len(payload) >= 3 and payload[0] == 0x16 and payload[1] == 0x03:
                logger.debug("Detected TLS ClientHello")
                return True

        # Check for HTTP request (port 80)
        if tcp.dport == 80:
            payload = bytes(tcp.payload)
            # HTTP methods: GET, POST, HEAD, etc.
            if payload.startswith(b'GET ') or payload.startswith(b'POST ') or payload.startswith(b'HEAD '):
                logger.debug("Detected HTTP request")
                return True

        return False

    def _handle_packet(self, nfq_packet):
        """
        Callback for NFQUEUE packets.

        Args:
            nfq_packet: NetfilterQueue packet object
        """
        self.stats['processed'] += 1

        try:
            # Parse packet
            pkt = self._parse_packet(nfq_packet.get_payload())
            if not pkt:
                nfq_packet.accept()
                self.stats['accepted'] += 1
                return

            # Check if we should bypass DPI
            if self._should_bypass(pkt):
                # Extract packet info
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                seq = pkt[TCP].seq

                # Inject random garbage BEFORE releasing real packet
                # DPI sees fake first → gets confused
                # Server sees both → ignores fake (garbage) → accepts real
                self.injector.inject_random_garbage(
                    src_ip, dst_ip, src_port, dst_port, seq
                )

                self.stats['bypassed'] += 1
                logger.debug(f"DPI bypass triggered: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

            # Always accept the real packet
            nfq_packet.accept()
            self.stats['accepted'] += 1

        except Exception as e:
            logger.error(f"Error handling packet: {e}")
            # Accept packet even on error to avoid breaking connection
            nfq_packet.accept()
            self.stats['accepted'] += 1

    def start(self):
        """
        Start NFQUEUE handler.

        This is a blocking call that runs the packet processing loop.
        """
        logger.info(f"Starting NFQUEUE handler on queue {self.queue_num}")

        self.nfqueue = NetfilterQueue()
        self.nfqueue.bind(self.queue_num, self._handle_packet)

        try:
            logger.info("whyDPI is running. Press Ctrl+C to stop.")
            self.nfqueue.run()
        except KeyboardInterrupt:
            logger.info("Received Ctrl+C, stopping...")
        finally:
            self.stop()

    def stop(self):
        """Stop NFQUEUE handler."""
        if self.nfqueue:
            logger.info("Stopping NFQUEUE handler")
            self.nfqueue.unbind()
            self.nfqueue = None

    def get_stats(self):
        """Get handler statistics."""
        stats = self.stats.copy()
        stats['injection_stats'] = self.injector.get_stats()
        return stats
