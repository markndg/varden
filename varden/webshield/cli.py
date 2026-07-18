from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .engine import scan_registration
from .evaluate import run_evaluation
from .models import ScanContext, ScanResult, WebMCPToolDefinition
from .sanitize import sanitize_tool

def _safe_cli_text(value: Any) -> str:
    """Escape attacker-controlled text before printing it to a terminal.

    ``varden web-shield scan``/``explain`` read an arbitrary JSON file that
    may itself be attacker-supplied (e.g. captured from a hostile page). Tool
    names, origins, and schema field paths flow from that file straight into
    ``print()`` calls; without escaping, embedded ANSI/terminal escape
    sequences or raw newlines could manipulate the developer's terminal
    (clearing the screen, spoofing prompts, hiding output) or inject fake
    log lines. ``repr()`` already protects the ``evidence``/diff fields
    below; this covers the remaining attacker-controlled fields that are
    printed as plain (non-``repr``) text. See
    docs/web-shield-hardening-review.md #12.
    """

    text = str(value)
    return "".join(ch if (ch == "\t" or (ch.isprintable() and ch not in "\x7f")) else repr(ch)[1:-1] for ch in text)


BAND_SUGGESTED_DECISION = {
    "low": "allow",
    "guarded": "monitor",
    "suspicious": "warn",
    "high": "require_approval",
    "critical": "block",
}


def _load_tool_file(path: str) -> tuple[WebMCPToolDefinition, ScanContext]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if "tool" in raw:
        tool_raw = raw["tool"]
        owner_origin = raw.get("owner_origin", "https://example.local")
        top_origin = raw.get("top_origin", owner_origin)
        api_surface = raw.get("api_surface", "document_model_context")
        context_raw = raw.get("context") or {}
    else:
        tool_raw = raw
        owner_origin = "https://example.local"
        top_origin = owner_origin
        api_surface = "document_model_context"
        context_raw = {}
    tool = WebMCPToolDefinition.from_raw(tool_raw, owner_origin=owner_origin, top_origin=top_origin, api_surface=api_surface)
    context = ScanContext(
        is_third_party_frame=bool(context_raw.get("is_third_party_frame", False)),
        https=bool(context_raw.get("https", owner_origin.startswith("https://"))),
        existing_tool_names=list(context_raw.get("existing_tool_names") or []),
        first_seen=bool(context_raw.get("first_seen", True)),
        registration_count_recent=int(context_raw.get("registration_count_recent", 0)),
        trust_state=context_raw.get("trust_state"),
        prior_violation_count=int(context_raw.get("prior_violation_count", 0)),
    )
    return tool, context


def suggest_decision(result: ScanResult, blocked_by_sanitizer: bool) -> str:
    if blocked_by_sanitizer:
        return "block"
    return BAND_SUGGESTED_DECISION.get(result.risk.band, "monitor")


def cmd_scan(path: str, *, human: bool = False) -> int:
    tool, context = _load_tool_file(path)
    result = scan_registration(tool, context)
    sanitized = sanitize_tool(tool)
    payload = result.to_dict()
    payload["suggested_decision"] = suggest_decision(result, sanitized.blocked)
    payload["sanitizer"] = {"blocked": sanitized.blocked, "unrepairable_fields": sanitized.unrepairable_fields}
    if human:
        _print_human(result, sanitized, payload["suggested_decision"])
    else:
        print(json.dumps(payload, indent=2))
    return 0


def cmd_explain(path: str) -> int:
    tool, context = _load_tool_file(path)
    result = scan_registration(tool, context)
    sanitized = sanitize_tool(tool)
    decision = suggest_decision(result, sanitized.blocked)
    _print_human(result, sanitized, decision)
    return 0


def _print_human(result: ScanResult, sanitized, decision: str) -> None:
    print(f"Tool: {_safe_cli_text(result.tool.name)}  (origin: {_safe_cli_text(result.tool.owner_origin)})")
    print(f"Risk score: {result.risk.score}/100  band={result.risk.band}  profile v{result.risk.profile_version}")
    print(f"Suggested decision (evidence only — Varden policy is authoritative): {decision}")
    print(f"Observed hash:            {result.exact_hash[:16]}…")
    print(f"Structural hash:          {result.structural_hash[:16]}…")
    print(f"Security-normalised hash: {result.canonical_hash[:16]}…")
    print()
    if not result.findings:
        print("No findings.")
    else:
        print(f"Findings ({len(result.findings)}):")
        for f in result.findings:
            print(f"  [{f.severity.upper():8}] {f.rule_id}  field={_safe_cli_text(f.field_path)}")
            print(f"      category: {f.category}  confidence: {f.confidence:.2f}")
            print(f"      {f.explanation}")
            if f.evidence:
                print(f"      evidence: {f.evidence!r}")
            print(f"      remediation: {f.remediation}")
    print()
    c = result.risk.components
    print(
        f"Risk components: content={c.content_risk} capability={c.capability_risk} "
        f"lifecycle={c.lifecycle_risk} provenance={c.provenance_risk} impact={c.impact_risk} "
        f"(only provenance can be reduced by local trust)"
    )
    print()
    print("Risk drivers:")
    for d in result.risk.drivers:
        print(f"  {d.contribution:+3d}  {d.rule_id:<28} {d.reason}")
    print()
    if sanitized.diff:
        print("Sanitisation preview:")
        for field_path, d in sanitized.diff.items():
            print(f"  {_safe_cli_text(field_path)}: {d['before']!r} -> {d['after']!r}")
        if sanitized.unrepairable_fields:
            print(f"  UNREPAIRABLE (recommend block, not sanitise): {', '.join(sanitized.unrepairable_fields)}")


def cmd_evaluate(*, corpus_version: str = "v1", human: bool = True) -> int:
    report = run_evaluation(corpus_version)
    if human:
        print(f"Web Shield evaluation — corpus v{report['corpus_version']} ({report['total_cases']} cases)")
        print(f"  precision={report['precision']:.3f}  recall={report['recall']:.3f}  f1={report['f1']:.3f}")
        print(f"  tp={report['true_positives']} fp={report['false_positives']} tn={report['true_negatives']} fn={report['false_negatives']}")
        print(f"  latency p50={report['latency_ms']['p50']}ms p95={report['latency_ms']['p95']}ms p99={report['latency_ms']['p99']}ms")
        print()
        print("  Per-category:")
        for category, stats in sorted(report["per_category"].items()):
            print(f"    {category:<28} {stats['correct']}/{stats['total']}")
        if report["top_false_positives"]:
            print()
            print("  False positives:")
            for fp in report["top_false_positives"]:
                print(f"    {fp['id']} (score={fp['score']}, band={fp['band']}) — {fp['notes']}")
        if report["top_misses"]:
            print()
            print("  Misses:")
            for miss in report["top_misses"]:
                print(f"    {miss['id']} (score={miss['score']}, band={miss['band']}) — {miss['notes']}")
        print()
        targets = report["acceptance_targets"]
        result = report["acceptance_result"]
        print("  Acceptance targets:")
        print(f"    recall >= {targets['malicious_recall_min']}: {'MET' if result['recall_met'] else 'NOT MET'} ({report['recall']})")
        print(f"    precision >= {targets['benign_precision_min']}: {'MET' if result['precision_met'] else 'NOT MET'} ({report['precision']})")
        print(f"    p95 latency < {targets['p95_latency_ms_max']}ms: {'MET' if result['latency_met'] else 'NOT MET'} ({report['latency_ms']['p95']}ms)")
    else:
        print(json.dumps(report, indent=2))
    return 0


def webshield_argv(args: Any) -> int:
    command = getattr(args, "web_shield_command", None)
    if command == "scan":
        return cmd_scan(args.tool_file, human=args.human)
    if command == "explain":
        return cmd_explain(args.tool_file)
    if command == "evaluate":
        return cmd_evaluate(corpus_version=args.corpus_version, human=not args.json)
    if command == "demo":
        from .demo import run_web_shield_demo
        return run_web_shield_demo(host=args.host, port=args.port, open_browser=not args.no_browser)
    if command == "extension":
        from .extension_build import build_extension, extension_path
        if args.extension_command == "build":
            return build_extension(args.out)
        if args.extension_command == "path":
            print(extension_path())
            return 0
    if command == "trust":
        from .trust_cli import trust_argv
        return trust_argv(args)
    print("Unknown web-shield command.", file=sys.stderr)
    return 2
