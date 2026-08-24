"""Taint propagation and explicit typed sanitisers.

Provenance never decays with depth. Only an explicit, typed sanitiser may
remove specific instruction-like taints — and even then ancestry remains.
LLM transformation never removes provenance or trust elevation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .models import ProvenanceSource, TaintSet, TaintedValue, content_hash, min_trust, new_id


def merge_sources(*groups: list[ProvenanceSource]) -> list[ProvenanceSource]:
    seen: set[str] = set()
    out: list[ProvenanceSource] = []
    for group in groups:
        for src in group:
            if src.source_id in seen:
                continue
            seen.add(src.source_id)
            out.append(src)
    return out


def propagate_taint(*taints: TaintSet) -> TaintSet:
    merged = TaintSet()
    for t in taints:
        merged.merge(t)
    # Sanitised does not cancel other taints by itself — sanitisers must
    # construct a new TaintSet deliberately.
    return merged


def tag_from_source(source: ProvenanceSource) -> TaintSet:
    t = TaintSet()
    if source.source_type == "user" and source.trust_level == "trusted" and source.integrity == "verified":
        t.add("user_authorised")
        return t
    if source.trust_level in {"untrusted", "hostile"}:
        t.add("external_input")
        if source.source_type in {"mcp_tool_definition", "webmcp_tool"}:
            t.add("untrusted_tool_metadata")
        if source.source_type in {"mcp_tool_response", "http_response", "web_page", "email", "command_output"}:
            t.add("untrusted_tool_output")
        if source.trust_level == "hostile":
            t.add("untrusted_instruction")
    if source.source_type in {"web_page", "webmcp_tool"} and source.metadata.get("cross_origin"):
        t.add("cross_origin")
    if source.trust_level == "unknown" or not source.provenance_complete:
        t.add("external_input")
    return t


def infer_taints_from_classifiers(classifiers: dict[str, bool] | None) -> TaintSet:
    t = TaintSet()
    classifiers = classifiers or {}
    if classifiers.get("secrets") or classifiers.get("credentials"):
        t.add("secret").add("credential")
    if classifiers.get("internal"):
        t.add("internal_data")
    if classifiers.get("pii"):
        t.add("private_data")
    return t


@dataclass
class Sanitiser:
    """Explicit typed sanitiser. No generic magic ``sanitize(text)``."""

    sanitiser_id: str
    version: str
    accepted_input_taints: set[str]
    output_taints: set[str]
    validation: str
    _fn: Callable[[Any], Any] | None = field(default=None, repr=False)

    def apply(self, tainted: TaintedValue) -> TaintedValue:
        if self._fn is None:
            raise RuntimeError(f"sanitiser {self.sanitiser_id} has no implementation")
        # Reject if input carries taints outside the accepted set (except
        # ones the sanitiser is designed to strip).
        disallowed = tainted.taints.tags - self.accepted_input_taints - {"sanitised"}
        # Secrets/credentials must never be stripped by a generic parser.
        if disallowed & {"secret", "credential", "private_data"}:
            raise ValueError(f"sanitiser {self.sanitiser_id} cannot accept secret/private taints")
        value = self._fn(tainted.value)
        out_taints = TaintSet(tags=set(self.output_taints) | {"sanitised"})
        # Provenance ancestry is preserved — sanitisation removes instruction
        # semantics, not history.
        return TaintedValue(
            value=value,
            provenance=list(tainted.provenance),
            taints=out_taints,
            derived_from=list(tainted.derived_from) + [tainted.content_hash or content_hash(tainted.value)],
            content_hash=content_hash(value),
            sanitiser=f"{self.sanitiser_id}@{self.version}",
        )


def strict_integer_parser() -> Sanitiser:
    def _parse(value: Any) -> int:
        if isinstance(value, bool):
            raise ValueError("bool is not a strict integer")
        if isinstance(value, int):
            return value
        text = str(value).strip()
        if not text or not text.lstrip("-").isdigit():
            raise ValueError("not an integer")
        return int(text)

    return Sanitiser(
        sanitiser_id="strict_integer_parser",
        version="1",
        accepted_input_taints={
            "external_input", "untrusted_instruction", "untrusted_tool_output",
            "untrusted_tool_metadata", "cross_origin", "user_authorised", "sanitised",
        },
        output_taints=set(),  # pure integer — instruction taint removed
        validation="decimal-integer",
        _fn=_parse,
    )


def strict_enum_parser(allowed: set[str]) -> Sanitiser:
    allowed_norm = {str(a) for a in allowed}

    def _parse(value: Any) -> str:
        text = str(value).strip()
        if text not in allowed_norm:
            raise ValueError(f"value not in enum {sorted(allowed_norm)}")
        return text

    return Sanitiser(
        sanitiser_id="strict_enum_parser",
        version="1",
        accepted_input_taints={
            "external_input", "untrusted_instruction", "untrusted_tool_output",
            "untrusted_tool_metadata", "cross_origin", "user_authorised", "sanitised",
        },
        output_taints=set(),
        validation=f"enum:{','.join(sorted(allowed_norm))}",
        _fn=_parse,
    )


def llm_transform_preserves_taint(tainted: TaintedValue, new_value: Any) -> TaintedValue:
    """LLM summarisation / rewrite NEVER elevates trust or clears taint."""
    taints = TaintSet().merge(tainted.taints)
    # Mark that content still carries untrusted instruction risk.
    if tainted.taints.is_untrusted() or any(s.trust_level in {"untrusted", "hostile", "unknown"} for s in tainted.provenance):
        taints.add("untrusted_instruction").add("external_input")
    return TaintedValue(
        value=new_value,
        provenance=list(tainted.provenance) + [
            ProvenanceSource(
                source_id=new_id("src"),
                source_type="generated",
                origin="llm",
                trust_level=min_trust(*(s.trust_level for s in tainted.provenance) or ["unknown"]),
                integrity="unverified",
                provenance_complete=True,
                metadata={"note": "llm_transform_does_not_clear_provenance"},
            )
        ],
        taints=taints,
        derived_from=list(tainted.derived_from) + [tainted.content_hash],
        content_hash=content_hash(new_value),
        sanitiser=None,
    )
