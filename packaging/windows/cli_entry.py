# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""PyInstaller entry point for the Windows CLI executable.

The CLI is rarely the primary UX on Windows — most users live in the
tray — but the exe is useful for troubleshooting (``whydpi start
--verbose`` in an elevated PowerShell prints the same diagnostics Linux
users see from ``journalctl``).
"""

from __future__ import annotations

import sys

from whydpi.cli import main


if __name__ == "__main__":
    sys.exit(main())
