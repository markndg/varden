from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass


@dataclass
class BucketConfig:
    rate_per_window: int
    window_seconds: int = 60
    burst_multiplier: float = 1.5

    @property
    def refill_per_second(self) -> float:
        return self.rate_per_window / float(self.window_seconds)

    @property
    def capacity(self) -> float:
        return max(float(self.rate_per_window), float(self.rate_per_window) * float(self.burst_multiplier))


class RateLimiter:
    """Simple scoped token-bucket limiter.

    Designed for control-plane workloads where read traffic, write traffic,
    ingest traffic, and long-lived stream connections need different budgets.
    """

    def __init__(self, default: BucketConfig, scoped: dict[str, BucketConfig] | None = None):
        self.default = default
        self.scoped = scoped or {}
        self._state: dict[tuple[str, str], tuple[float, float]] = {}

    def _config(self, scope: str) -> BucketConfig:
        return self.scoped.get(scope, self.default)

    def allow(self, key: str, scope: str = 'default', cost: float = 1.0) -> bool:
        cfg = self._config(scope)
        now = time.time()
        state_key = (scope, key)
        tokens, updated_at = self._state.get(state_key, (cfg.capacity, now))
        elapsed = max(0.0, now - updated_at)
        tokens = min(cfg.capacity, tokens + (elapsed * cfg.refill_per_second))
        if tokens < cost:
            self._state[state_key] = (tokens, now)
            return False
        self._state[state_key] = (tokens - cost, now)
        return True

    def retry_after(self, key: str, scope: str = 'default', cost: float = 1.0) -> int:
        cfg = self._config(scope)
        now = time.time()
        state_key = (scope, key)
        tokens, updated_at = self._state.get(state_key, (cfg.capacity, now))
        elapsed = max(0.0, now - updated_at)
        tokens = min(cfg.capacity, tokens + (elapsed * cfg.refill_per_second))
        missing = max(0.0, cost - tokens)
        if missing <= 0:
            return 0
        seconds = missing / max(cfg.refill_per_second, 0.001)
        return max(1, int(seconds))
