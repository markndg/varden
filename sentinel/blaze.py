from __future__ import annotations
import json, subprocess
from dataclasses import dataclass

@dataclass
class RouteDecision:
    target: str
    reason: str

class BlazeRuntime:
    def __init__(self, command=None):
        self.command = command or []
    def route(self, classifiers: dict[str, bool], risk_score: int) -> RouteDecision:
        if classifiers.get("secrets") or classifiers.get("internal"):
            return RouteDecision("local_blaze", "sensitive content")
        if risk_score >= 80:
            return RouteDecision("local_blaze", "high risk")
        return RouteDecision("cloud", "default")
    def execute_local(self, payload):
        if not self.command:
            return {"runtime": "blaze", "status": "no_command_configured", "payload_preview": str(payload)[:200]}
        proc = subprocess.run(self.command, input=json.dumps(payload).encode("utf-8"), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        return {
            "runtime": "blaze",
            "returncode": proc.returncode,
            "stdout": proc.stdout.decode("utf-8", errors="replace"),
            "stderr": proc.stderr.decode("utf-8", errors="replace"),
        }
