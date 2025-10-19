# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT
# For educational and research purposes only

"""
whyDPI - Educational DPI Bypass Tool
====================================

A minimal, educational tool for understanding and researching
Deep Packet Inspection (DPI) bypass techniques.

⚠️ For educational and research purposes only.
"""

__version__ = "0.1.0"
__author__ = "whyDPI Contributors"
__license__ = "MIT"

from .packet_injector import PacketInjector
from .nfqueue_handler import NFQueueHandler
from .dns_config import DNSConfig

__all__ = ['PacketInjector', 'NFQueueHandler', 'DNSConfig']
