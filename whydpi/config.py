# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT
# For educational and research purposes only

"""
Configuration module for whyDPI

100% independent implementation - no external code dependencies
"""

# Default configuration
DEFAULT_QUEUE_NUM = 200
DEFAULT_TTL = 3  # Low TTL - reaches DPI but expires before server
DEFAULT_PORTS = [80, 443]

# DNS Configuration
YANDEX_DNS_PRIMARY = "77.88.8.8"
YANDEX_DNS_SECONDARY = "77.88.8.1"

# Fake Packet Configuration
# Instead of real packet fragmentation, use simple random garbage
# This is simpler and more effective for most DPI systems
FAKE_PACKET_SIZE = 500  # Size of fake garbage packet
USE_RANDOM_FAKE = True  # Use random garbage instead of real packet fragments
