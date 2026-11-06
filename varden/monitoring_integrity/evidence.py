"""Append-only integrity evidence.

The hash chain is tamper-evident relative to a head stored outside the
agent's reach. It is not tamper-proof. Replacing the file and every copy of
the head removes the evidence. This is the same limit as Varden's audit chain.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Any

from .io_guard import internal_io


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


class EvidenceLog:
    def __init__(self, path: str | None = None) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._head = "0" * 64
        self._records: list[dict[str, Any]] = []
        if path and os.path.isfile(path):
            self._reload(path)

    def _reload(self, path: str) -> None:
        previous = "0" * 64
        with internal_io():
            with open(path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    record = json.loads(line)
                    if record.get("prev_hash") != previous:
                        self._records.append({"integrity": "chain_break", "prev_hash": previous})
                        break
                    body = {key: value for key, value in record.items() if key != "hash"}
                    digest = hashlib.sha256(_canonical(body)).hexdigest()
                    if digest != record.get("hash"):
                        self._records.append({"integrity": "hash_mismatch"})
                        break
                    self._records.append(record)
                    previous = str(record["hash"])
        self._head = previous

    @property
    def head(self) -> str:
        with self._lock:
            return self._head

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            body = {
                "timestamp": time.time(),
                "prev_hash": self._head,
                "event": event,
            }
            digest = hashlib.sha256(_canonical(body)).hexdigest()
            record = dict(body)
            record["hash"] = digest
            self._records.append(record)
            self._head = digest
            if self.path:
                directory = os.path.dirname(self.path)
                if directory:
                    os.makedirs(directory, exist_ok=True)
                with internal_io():
                    with open(self.path, "a", encoding="utf-8") as handle:
                        handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")
            return record

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._records)

    def verify_chain(self) -> dict[str, Any]:
        previous = "0" * 64
        for index, record in enumerate(self.records()):
            if record.get("integrity") in {"chain_break", "hash_mismatch"}:
                return {"ok": False, "reason": record["integrity"], "index": index}
            body = {key: value for key, value in record.items() if key != "hash"}
            digest = hashlib.sha256(_canonical(body)).hexdigest()
            if record.get("prev_hash") != previous or digest != record.get("hash"):
                return {"ok": False, "reason": "chain_mismatch", "index": index}
            previous = digest
        return {"ok": True, "head": previous, "count": len(self._records)}
