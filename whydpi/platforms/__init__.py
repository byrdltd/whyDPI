# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Per-platform engine implementations.

``whydpi.core.engine`` is a thin dispatcher that imports from this
package based on ``sys.platform``; all platform-specific wiring (netfilter
on Linux, WinDivert on Windows) lives here so the cross-platform core
never grows a pile of ``if platform ==`` checks.
"""
