"""
whyDPI - Educational DPI Bypass Tool

Main CLI entry point.
"""

import argparse
import logging
import sys
import os
import subprocess
from .nfqueue_handler import NFQueueHandler
from .dns_config import DNSConfig
from .config import DEFAULT_QUEUE_NUM, DEFAULT_TTL, DEFAULT_PORTS

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def check_root():
    """Check if running as root."""
    if os.geteuid() != 0:
        logger.error("whyDPI requires root privileges")
        logger.error("Please run with sudo: sudo python3 -m whydpi")
        sys.exit(1)


def setup_iptables(queue_num, ports):
    """
    Setup iptables NFQUEUE rules.

    Args:
        queue_num (int): NFQUEUE number
        ports (list): List of ports to intercept
    """
    logger.info("Setting up iptables rules...")

    try:
        # Clear existing rules for this queue
        subprocess.run(
            ['iptables', '-t', 'mangle', '-D', 'POSTROUTING', '-j', 'NFQUEUE', '--queue-num', str(queue_num)],
            check=False,
            capture_output=True
        )

        # Add rules for each port
        for port in ports:
            cmd = [
                'iptables', '-t', 'mangle', '-A', 'POSTROUTING',
                '-p', 'tcp', '--dport', str(port),
                '-j', 'NFQUEUE', '--queue-num', str(queue_num), '--queue-bypass'
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            logger.info(f"Added iptables rule for port {port}")

        logger.info("iptables rules configured successfully")
        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to setup iptables: {e}")
        return False


def cleanup_iptables(queue_num):
    """
    Remove iptables NFQUEUE rules.

    Args:
        queue_num (int): NFQUEUE number
    """
    logger.info("Cleaning up iptables rules...")

    try:
        # Remove all rules for this queue
        while True:
            result = subprocess.run(
                ['iptables', '-t', 'mangle', '-D', 'POSTROUTING', '-j', 'NFQUEUE', '--queue-num', str(queue_num)],
                capture_output=True
            )
            if result.returncode != 0:
                break

        logger.info("iptables rules cleaned up")

    except Exception as e:
        logger.error(f"Failed to cleanup iptables: {e}")


def cmd_start(args):
    """Start whyDPI daemon."""
    check_root()

    logger.info("=" * 60)
    logger.info("whyDPI - Educational DPI Bypass Tool")
    logger.info("=" * 60)
    logger.info("⚠️  For educational and research purposes only")
    logger.info("=" * 60)

    # Configure DNS if requested
    if args.configure_dns:
        if DNSConfig.is_configured():
            logger.info("DNS already configured with Yandex DNS")
        else:
            logger.info("Configuring DNS...")
            if not DNSConfig.configure():
                logger.error("DNS configuration failed")
                sys.exit(1)

    # Setup iptables
    if not setup_iptables(args.queue, args.ports):
        logger.error("iptables setup failed")
        sys.exit(1)

    # Start NFQUEUE handler
    try:
        handler = NFQueueHandler(
            queue_num=args.queue,
            ttl=args.ttl,
            ports=args.ports
        )
        handler.start()  # Blocking call

    except KeyboardInterrupt:
        logger.info("\nReceived Ctrl+C, shutting down...")

    except Exception as e:
        logger.error(f"Error: {e}")

    finally:
        # Cleanup
        cleanup_iptables(args.queue)
        logger.info("whyDPI stopped")


def cmd_stop(args):
    """Stop whyDPI (cleanup)."""
    check_root()

    logger.info("Stopping whyDPI...")
    cleanup_iptables(args.queue)
    logger.info("whyDPI stopped successfully")


def cmd_dns_configure(args):
    """Configure DNS."""
    check_root()

    if DNSConfig.is_configured():
        logger.info("DNS already configured with Yandex DNS")
        return

    logger.info("Configuring DNS...")
    if DNSConfig.configure():
        logger.info("DNS configured successfully")
    else:
        logger.error("DNS configuration failed")
        sys.exit(1)


def cmd_dns_restore(args):
    """Restore original DNS."""
    check_root()

    logger.info("Restoring DNS...")
    if DNSConfig.restore():
        logger.info("DNS restored successfully")
    else:
        logger.error("DNS restoration failed")
        sys.exit(1)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='whyDPI - Educational DPI bypass tool for research purposes',
        epilog='⚠️  For educational and research purposes only. Use responsibly.'
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Start command
    start_parser = subparsers.add_parser('start', help='Start whyDPI')
    start_parser.add_argument(
        '-q', '--queue',
        type=int,
        default=DEFAULT_QUEUE_NUM,
        help=f'NFQUEUE number (default: {DEFAULT_QUEUE_NUM})'
    )
    start_parser.add_argument(
        '-t', '--ttl',
        type=int,
        default=DEFAULT_TTL,
        help=f'TTL for fake packets (default: {DEFAULT_TTL})'
    )
    start_parser.add_argument(
        '-p', '--ports',
        nargs='+',
        type=int,
        default=DEFAULT_PORTS,
        help=f'Ports to intercept (default: {DEFAULT_PORTS})'
    )
    start_parser.add_argument(
        '--configure-dns',
        action='store_true',
        help='Configure Yandex DNS before starting'
    )
    start_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    start_parser.set_defaults(func=cmd_start)

    # Stop command
    stop_parser = subparsers.add_parser('stop', help='Stop whyDPI (cleanup iptables)')
    stop_parser.add_argument(
        '-q', '--queue',
        type=int,
        default=DEFAULT_QUEUE_NUM,
        help=f'NFQUEUE number (default: {DEFAULT_QUEUE_NUM})'
    )
    stop_parser.set_defaults(func=cmd_stop)

    # DNS configure
    dns_conf_parser = subparsers.add_parser('dns-configure', help='Configure Yandex DNS')
    dns_conf_parser.set_defaults(func=cmd_dns_configure)

    # DNS restore
    dns_restore_parser = subparsers.add_parser('dns-restore', help='Restore original DNS')
    dns_restore_parser.set_defaults(func=cmd_dns_restore)

    args = parser.parse_args()

    # Set log level
    if hasattr(args, 'verbose') and args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Execute command
    if args.command:
        args.func(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
