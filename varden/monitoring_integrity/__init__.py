"""Monitoring Integrity Protection.

In-process hooks block patched calls. They are not an independent boundary.
OS enforcement is a supervisor-launched profile or a separate Unix user, and
only a fresh probe may report that boundary as verified.
See ``docs/monitoring-integrity-boundary.md``.
"""

from __future__ import annotations

from .service import (
    apply_to_decision,
    disable_monitoring_integrity,
    enable_monitoring_integrity,
    enabled,
    path_requires_mediation,
    posture,
    precheck_action,
    reset_monitoring_integrity,
)

__all__ = [
    "apply_to_decision",
    "disable_monitoring_integrity",
    "enable_monitoring_integrity",
    "enabled",
    "path_requires_mediation",
    "posture",
    "precheck_action",
    "reset_monitoring_integrity",
]
