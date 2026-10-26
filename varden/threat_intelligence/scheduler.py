"""Optional polling thread.

Started only when threat intelligence is enabled. A failed poll never touches
enforcement. Intervals come from configuration, with jitter so sources do not
align on one clock.
"""

from __future__ import annotations

import random
import threading
import time

from .service import ThreatIntelService


class IntelligenceScheduler:
    def __init__(self, service: ThreatIntelService, *, rng: random.Random | None = None) -> None:
        self.service = service
        self._rng = rng or random.Random()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if not self.service.config.enabled or self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="varden-threat-intelligence", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def run_due(self, now: float | None = None) -> list[str]:
        """Run sources whose next_due has passed. Returns the source ids checked."""
        if not self.service.config.enabled:
            return []
        moment = time.time() if now is None else now
        due: list[str] = []
        for view in self.service.source_views():
            source_id = view["source_id"]
            next_due = view.get("next_due")
            if next_due is None or float(next_due) <= moment:
                due.append(source_id)
        for source_id in due:
            try:
                self.service.check(source_id)
            except Exception:
                # Source errors are recorded by the service. Keep going.
                continue
        return due

    def _loop(self) -> None:
        while not self._stop.is_set():
            interval = min(self.service.config.interval_for(source_id) for source_id in self.service.sources)
            jitter = interval * self.service.config.jitter_ratio * self._rng.random()
            if self._stop.wait(min(30.0, max(1.0, interval * 0.01) + jitter)):
                return
            self.run_due()
