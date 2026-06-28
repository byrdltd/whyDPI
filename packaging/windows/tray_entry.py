# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""PyInstaller entry point for the Windows tray executable.

Kept deliberately trivial so the exe's behaviour matches ``whydpi-tray``
as installed via pip.  Do not add logic here — extend
:mod:`whydpi.ui.tray` instead.
"""

from __future__ import annotations

import sys

from whydpi.ui.tray import run


if __name__ == "__main__":
    sys.exit(run())
