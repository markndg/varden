"""External threat intelligence.

Advisory only. Nothing in this package is consulted by the runtime firewall.
Downloaded feeds are untrusted data and never become enforcement rules until
an operator approves a candidate through Varden's normal policy mechanism.
"""

from __future__ import annotations

SCHEMA_VERSION = 1

__all__ = ["SCHEMA_VERSION"]
