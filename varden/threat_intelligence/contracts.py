"""Varden security contracts.

A contract states an invariant. It is not an executable rule. Mapping from
external records uses structured identifiers only (ATLAS technique ids, CWE
ids, OWASP ASI ids). Free-text threat descriptions never select a contract.
"""

from __future__ import annotations

from typing import Any

from .models import GENERATION_VERSION, ThreatIntelligenceItem

CONTRACT_VERSION = "1"

# Explicit bindings. Unknown identifiers do not guess a contract.
ATLAS_TECHNIQUE_MAP: dict[str, str] = {
    # Published ATLAS technique ids. Names are for operators reading the table;
    # matching uses the id only.
    "AML.T0051": "untrusted-instruction-execution",  # LLM Prompt Injection
    "AML.T0054": "untrusted-instruction-execution",  # LLM Jailbreak
}

CWE_MAP: dict[str, str] = {
    "CWE-200": "credential-exfiltration",
    "CWE-312": "credential-exfiltration",
    "CWE-522": "credential-exfiltration",
    "CWE-798": "credential-exfiltration",
    "CWE-77": "unexpected-code-execution",
    "CWE-78": "unexpected-code-execution",
    "CWE-94": "unexpected-code-execution",
    "CWE-269": "privilege-amplification",
}

# Seen, structured, and deliberately not translated into a rule.
REVIEW_ONLY: dict[str, str] = {
    "CWE-287": "Improper authentication has no single Varden rule that this installation can prove.",
    "CWE-306": "Missing authentication has no single Varden rule that this installation can prove.",
    "CWE-918": "Server-side request forgery needs a destination constraint; a blanket HTTP rule would be false confidence.",
    "ASI04": "Agentic supply-chain weaknesses are not translated into a runtime rule without a specific component binding.",
    "ASI06": "Memory and context poisoning is not translated into a Varden rule without a memory surface Varden can prove.",
    "ASI07": "Inter-agent communication is not a Varden enforcement surface.",
    "ASI08": "Cascading failures are not a single enforceable invariant.",
    "ASI09": "Human-agent trust exploitation is not translated into a rule that would claim to police operator judgement.",
    "ASI10": "Rogue-agent behaviour is not deterministically detectable as a Varden policy predicate.",
}

OWASP_MAP: dict[str, str] = {
    "ASI01": "untrusted-instruction-execution",
    "ASI02": "unexpected-code-execution",
    "ASI03": "privilege-amplification",
    "ASI05": "unexpected-code-execution",
}

_CONTRACTS: dict[str, dict[str, Any]] = {
    "untrusted-instruction-execution": {
        "invariant": "untrusted_content_must_not_gain_the_agents_authority",
        "required_observability": ["provenance", "authority_flow", "tool_invocation", "data_classification"],
        "unacceptable_outcomes": ["privilege_amplification", "provenance_loss", "untrusted_to_privileged"],
        "enforcement_surfaces": ["tools", "mcp", "subprocess", "filesystem"],
        "required_surfaces": ["tools", "mcp", "subprocess", "filesystem"],
        "proof": {"type": "tool_call", "classifier:provenance_untrusted": True},
        "candidate_rule": {
            "id": "ti-untrusted-instruction-execution",
            "description": "Require approval when a tool call carries untrusted provenance. Varden contract template; external prose is not part of this rule.",
            "tags": ["threat-intelligence", "contract:untrusted-instruction-execution"],
            "type": "tool_call",
            "classifier:provenance_untrusted": True,
        },
        "expected_action": "require_approval",
        "explanation": "Untrusted instructions must not be able to exercise the agent's tools, files, subprocesses, or MCP authority.",
    },
    "credential-exfiltration": {
        "invariant": "sensitive_information_must_not_cross_an_unauthorised_trust_boundary",
        "required_observability": ["provenance", "data_classification", "destination", "authority_flow"],
        "unacceptable_outcomes": ["sensitive_to_untrusted_destination", "provenance_loss"],
        "enforcement_surfaces": ["http", "mcp", "filesystem"],
        "required_surfaces": ["http", "mcp", "filesystem"],
        "proof": {"type": "http_request", "classifier:secrets": True},
        "candidate_rule": {
            "id": "ti-credential-exfiltration",
            "description": "Require approval before an HTTP request that contains secrets. Varden contract template; external prose is not part of this rule.",
            "tags": ["threat-intelligence", "contract:credential-exfiltration"],
            "type": "http_request",
            "classifier:secrets": True,
        },
        "expected_action": "require_approval",
        "explanation": "Secrets and credentials must not leave across an HTTP or MCP trust boundary that policy does not explicitly hold.",
    },
    "unexpected-code-execution": {
        "invariant": "untrusted_input_must_not_become_host_execution",
        "required_observability": ["tool_invocation", "provenance"],
        "unacceptable_outcomes": ["unexpected_code_execution", "privilege_amplification"],
        "enforcement_surfaces": ["subprocess", "tools"],
        "required_surfaces": ["subprocess", "tools"],
        "proof": {"type": "tool_call", "field:metadata.execution_surface": "subprocess"},
        "candidate_rule": {
            "id": "ti-unexpected-code-execution",
            "description": "Require approval for subprocess execution. Varden contract template; external prose is not part of this rule.",
            "tags": ["threat-intelligence", "contract:unexpected-code-execution"],
            "type": "tool_call",
            "field:metadata.execution_surface": "subprocess",
        },
        "expected_action": "require_approval",
        "explanation": "Host execution must not be reachable from agent tool dispatch unless policy holds the call for approval.",
    },
    "privilege-amplification": {
        "invariant": "an_action_must_not_silently_expand_authority",
        "required_observability": ["authority_flow", "provenance", "tool_invocation"],
        "unacceptable_outcomes": ["privilege_amplification", "provenance_loss"],
        "enforcement_surfaces": ["tools", "mcp"],
        "required_surfaces": ["tools", "mcp"],
        "proof": {"type": "tool_call", "classifier:authority_escalation": True},
        "candidate_rule": {
            "id": "ti-privilege-amplification",
            "description": "Require approval when authority escalation is classified. Varden contract template; external prose is not part of this rule.",
            "tags": ["threat-intelligence", "contract:privilege-amplification"],
            "type": "tool_call",
            "classifier:authority_escalation": True,
        },
        "expected_action": "require_approval",
        "explanation": "Tool and MCP actions that expand authority must be held unless an existing enforcing rule already covers that classifier.",
    },
}

CONTRACT_KEYS = frozenset(
    {
        "id",
        "version",
        "sources",
        "invariant",
        "required_observability",
        "unacceptable_outcomes",
        "enforcement_surfaces",
        "required_surfaces",
        "proof",
        "explanation",
        "mapping_ids",
        "mapping_version",
        "review_only",
        "review_reason",
    }
)


def _ids_for(item: ThreatIntelligenceItem) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for tech in item.techniques:
        found.append((tech.system or item.source, tech.id))
    for weak in item.weaknesses:
        found.append(("cwe", weak.id if weak.id.startswith("CWE-") else f"CWE-{weak.id}"))
    if item.source == "owasp":
        found.append(("owasp", item.source_id))
    if item.source == "atlas" and item.source_id:
        found.append(("atlas", item.source_id))
    if item.source == "cwe" and item.source_id:
        cid = item.source_id if str(item.source_id).startswith("CWE-") else f"CWE-{item.source_id}"
        found.append(("cwe", cid))
    return found


def select_contract_id(item: ThreatIntelligenceItem) -> tuple[str | None, str | None, list[str]]:
    """Return (contract_id, review_reason, matched_ids)."""
    matched: list[str] = []
    review_reason: str | None = None
    chosen: str | None = None
    for system, ident in _ids_for(item):
        key = ident.strip()
        if key in REVIEW_ONLY and chosen is None:
            review_reason = REVIEW_ONLY[key]
            matched.append(key)
            continue
        target = None
        if system in {"atlas", "mitre-atlas"} or key.startswith("AML."):
            target = ATLAS_TECHNIQUE_MAP.get(key)
        elif system == "cwe" or key.startswith("CWE-"):
            target = CWE_MAP.get(key)
        elif system == "owasp" or key.startswith("ASI"):
            target = OWASP_MAP.get(key)
            if target is None and key in REVIEW_ONLY:
                review_reason = REVIEW_ONLY[key]
                matched.append(key)
        if target:
            chosen = target
            matched.append(key)
    if chosen:
        return chosen, None, matched
    if review_reason:
        return None, review_reason, matched
    if item.techniques or item.weaknesses or item.source in {"atlas", "cwe", "owasp", "nvd"}:
        return None, "No deterministic Varden contract is bound to the structured identifiers in this record.", matched
    return None, "Source record has no structured technique, weakness, or entry id to map.", matched


def build_contract(item: ThreatIntelligenceItem) -> dict[str, Any] | None:
    contract_id, review_reason, matched = select_contract_id(item)
    sources = [
        {
            "type": item.source,
            "id": item.source_id,
            "upstream_url": item.upstream_url,
            "raw_content_hash": item.raw_content_hash,
            "source_version": item.source_version,
        }
    ]
    if contract_id is None:
        return {
            "id": None,
            "version": CONTRACT_VERSION,
            "sources": sources,
            "invariant": None,
            "required_observability": [],
            "unacceptable_outcomes": [],
            "enforcement_surfaces": [],
            "required_surfaces": [],
            "proof": None,
            "explanation": review_reason or "No contract.",
            "mapping_ids": matched,
            "mapping_version": GENERATION_VERSION,
            "review_only": True,
            "review_reason": review_reason,
        }
    spec = _CONTRACTS[contract_id]
    return {
        "id": contract_id,
        "version": CONTRACT_VERSION,
        "sources": sources,
        "invariant": spec["invariant"],
        "required_observability": list(spec["required_observability"]),
        "unacceptable_outcomes": list(spec["unacceptable_outcomes"]),
        "enforcement_surfaces": list(spec["enforcement_surfaces"]),
        "required_surfaces": list(spec["required_surfaces"]),
        "proof": dict(spec["proof"]),
        "explanation": spec["explanation"],
        "mapping_ids": matched,
        "mapping_version": GENERATION_VERSION,
        "review_only": False,
        "review_reason": None,
    }


def contract_template(contract_id: str) -> dict[str, Any] | None:
    spec = _CONTRACTS.get(contract_id)
    if not spec:
        return None
    return {
        "rule": dict(spec["candidate_rule"]),
        "expected_action": spec["expected_action"],
        "proof": dict(spec["proof"]),
        "required_surfaces": list(spec["required_surfaces"]),
        "required_observability": list(spec["required_observability"]),
    }


def validate_contract(doc: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ["contract must be an object"]
    unknown = set(doc) - CONTRACT_KEYS
    if unknown:
        errors.append("contract has unknown keys: " + ", ".join(sorted(unknown)))
    if doc.get("version") != CONTRACT_VERSION:
        errors.append("contract.version is not supported")
    if not isinstance(doc.get("sources"), list) or not doc["sources"]:
        errors.append("contract.sources must be a non-empty list")
    if doc.get("review_only"):
        if not doc.get("review_reason"):
            errors.append("review-only contract requires review_reason")
        return errors
    if not isinstance(doc.get("id"), str) or not doc.get("id"):
        errors.append("contract.id must be a non-empty string")
    if not isinstance(doc.get("invariant"), str) or not doc.get("invariant"):
        errors.append("contract.invariant must be a non-empty string")
    for key in ("required_observability", "unacceptable_outcomes", "enforcement_surfaces", "required_surfaces"):
        if not isinstance(doc.get(key), list):
            errors.append(f"contract.{key} must be a list")
    if not isinstance(doc.get("proof"), dict) or not doc.get("proof"):
        errors.append("contract.proof must be an object")
    return errors
