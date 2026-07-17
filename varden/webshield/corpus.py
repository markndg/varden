from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from .models import ScanContext, WebMCPToolDefinition


@dataclass
class CorpusCase:
    id: str
    label: str  # "benign" | "malicious"
    scan_target: str  # "registration" | "output"
    attack_category: str
    notes: str
    raw: dict[str, Any] = field(default_factory=dict)


def _corpus_path(version: str = "v1") -> Path:
    try:
        pkg = resources.files("varden.webshield").joinpath("corpus", f"cases_{version}.json")
        if pkg.is_file():
            return Path(str(pkg))
    except Exception:
        pass
    return Path(__file__).resolve().parent / "corpus" / f"cases_{version}.json"


def load_corpus(version: str = "v1") -> tuple[str, list[CorpusCase]]:
    path = _corpus_path(version)
    doc = json.loads(path.read_text(encoding="utf-8"))
    cases = [
        CorpusCase(
            id=row["id"],
            label=row["label"],
            scan_target=row.get("scan_target", "registration"),
            attack_category=row.get("attack_category", "uncategorised"),
            notes=row.get("notes", ""),
            raw=row,
        )
        for row in doc.get("cases", [])
    ]
    return doc.get("corpus_version", version), cases


def build_registration_inputs(case: CorpusCase) -> tuple[WebMCPToolDefinition, ScanContext]:
    raw = case.raw
    tool_raw = dict(raw.get("tool") or {})

    padding_repeat = raw.get("description_padding_repeat")
    if padding_repeat:
        filler = "This sentence is repeated only to exceed the safe metadata size limit for testing. "
        tool_raw["description"] = (filler * int(padding_repeat))[: int(padding_repeat) * len(filler)]

    context_raw = raw.get("context") or {}
    session_started_at = None
    registered_at = time.time()
    if "session_started_at_offset_seconds" in context_raw:
        session_started_at = time.time() - 10_000
        registered_at = session_started_at + float(context_raw.get("session_started_at_offset_seconds") or 0)
    if "registered_at_offset_seconds" in tool_raw:
        base = session_started_at if session_started_at is not None else time.time() - 10_000
        registered_at = base + float(tool_raw.pop("registered_at_offset_seconds"))

    tool = WebMCPToolDefinition.from_raw(
        tool_raw,
        owner_origin=context_raw.get("owner_origin", "https://example.test"),
        top_origin=context_raw.get("top_origin", context_raw.get("owner_origin", "https://example.test")),
        api_surface="document_model_context",
        registered_at=registered_at,
    )

    context = ScanContext(
        is_third_party_frame=bool(context_raw.get("is_third_party_frame", False)),
        https=bool(context_raw.get("https", True)),
        session_started_at=session_started_at,
        session_already_active=bool(context_raw.get("session_already_active", False)),
        existing_tool_names=list(context_raw.get("existing_tool_names") or []),
        previous_exact_hash=context_raw.get("previous_exact_hash"),
        previous_canonical_hash=context_raw.get("previous_canonical_hash"),
        first_seen=bool(context_raw.get("first_seen", True)),
        registration_count_recent=int(context_raw.get("registration_count_recent", 0)),
        trust_state=context_raw.get("trust_state"),
        prior_violation_count=int(context_raw.get("prior_violation_count", 0)),
    )
    return tool, context


def build_output_inputs(case: CorpusCase) -> dict[str, Any]:
    raw = case.raw
    return {
        "text": raw.get("output_text", ""),
        "owner_origin": raw.get("owner_origin", "https://example.test"),
        "contains_user_generated_content": bool(raw.get("contains_user_generated_content", False)),
    }
