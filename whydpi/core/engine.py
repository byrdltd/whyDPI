# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Platform-agnostic engine entry point.

Historically this module contained the Linux-specific lifecycle code
inline.  The Windows port introduced the ``whydpi.platforms`` subpackage
so each OS keeps its wiring isolated; this file now only decides which
backend to invoke based on :data:`sys.platform`.

The public API (``run``, ``stop_only``, ``build_runtime``) is preserved
so existing imports from :mod:`whydpi.cli` and friends keep working.
"""

from __future__ import annotations

import logging
import sys
from typing import Callable

from ..settings import Settings

logger = logging.getLogger(__name__)


def _backend():
    platform = sys.platform
    if platform.startswith("linux"):
        from ..platforms import linux as backend
        return backend
    if platform == "win32":
        from ..platforms import windows as backend
        return backend
    raise RuntimeError(f"whyDPI does not yet support platform: {platform!r}")


def run(settings: Settings, *, configure_resolver: bool,
        block_until: Callable[[], None] | None = None) -> int:
    return _backend().run(
        settings,
        configure_resolver=configure_resolver,
        block_until=block_until,
    )


def stop_only(settings: Settings) -> int:
    return _backend().stop_only(settings)


def build_runtime(settings: Settings, *, configure_resolver: bool):
    """Linux-only helper; kept for backwards compatibility with callers.

    On Windows this raises ``AttributeError`` because the Windows engine
    does not have a symmetrical :func:`build_runtime` abstraction — its
    state lives inside the :class:`~whydpi.system.windivert.PacketShaper`
    rather than a pre-assembled dataclass.
    """
    backend = _backend()
    try:
        return backend.build_runtime(  # type: ignore[attr-defined]
            settings, configure_resolver=configure_resolver,
        )
    except AttributeError as exc:
        raise RuntimeError(
            "build_runtime() is Linux-specific; callers on other platforms "
            "should use run() or stop_only() directly."
        ) from exc
