# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""System-tray icon powered by :mod:`pystray`.

Phase 1 skeleton.  The contract we are aiming for in Phase 3:

* A menu with **Start / Stop**, **Open cache folder**, **About**, **Quit**.
* Icon colour reflects state: indigo = running, grey = stopped,
  amber = starting/stopping transition, red = error.
* On Windows, clicking **Start** spawns the elevated engine process
  (the tray exe itself is already elevated thanks to the embedded UAC
  manifest, so no second prompt appears).
* On Linux, clicking **Start** runs ``systemctl start whydpi`` via
  polkit; read-only operations (status, cache view) work without
  elevation.

We postpone the ``pystray`` import and any GUI imports until
:func:`run` is actually invoked, so headless CI doesn't have to
install a graphical stack to verify the package parses.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def run() -> int:
    """Launch the tray icon.  Blocks until the user selects Quit."""
    raise NotImplementedError(
        "Tray UI lands in Phase 3 of the Windows port."
    )
