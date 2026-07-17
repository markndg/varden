from __future__ import annotations


class PolicyViolation(Exception):
    """Raised when a typed policy rule (e.g. token budget) denies an action."""

    def __init__(
        self,
        message: str,
        *,
        rule: dict | None = None,
        projected_usd: float = 0.0,
        current_usd: float = 0.0,
        limit_usd: float = 0.0,
    ):
        super().__init__(message)
        self.rule = rule or {}
        self.projected_usd = projected_usd
        self.current_usd = current_usd
        self.limit_usd = limit_usd
