"""JSON and HTML exports. Both render the sealed outcomes, not a second verdict."""

from __future__ import annotations

import html
import json
from typing import Any


def _cell(value: Any) -> str:
    return html.escape(json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value))


def _assurance_lines(record: dict[str, Any]) -> str:
    assurance = record.get("assurance") if isinstance(record.get("assurance"), dict) else {}
    labels = (
        ("sdk", "SDK-mediated protection"),
        ("os_supervised", "OS-supervised process"),
        ("unsupervised_same_user", "Unsupervised same-user process"),
    )
    lines = []
    for key, label in labels:
        item = assurance.get(key)
        if isinstance(item, dict) and item.get("verdict"):
            lines.append(f"<p class=\"verdict\">{_cell(label)}: {_cell(item.get('verdict'))}</p>")
    return "".join(lines)


def _production_lines(record: dict[str, Any]) -> str:
    entry = record.get("production_entry") if isinstance(record.get("production_entry"), dict) else {}
    cases = entry.get("cases") if isinstance(entry, dict) else None
    if not isinstance(cases, list) or not cases:
        return ""
    items = "".join(
        f"<li>{_cell(case.get('name'))}: {_cell(case.get('outcome'))}</li>"
        for case in cases
        if isinstance(case, dict)
    )
    return f"<h2>Production entry</h2><ul>{items}</ul>"


def _authority_line(record: dict[str, Any]) -> str:
    authority = record.get("authority") if isinstance(record.get("authority"), dict) else {}
    isolated = authority.get("isolated") if isinstance(authority, dict) else None
    if not isinstance(isolated, dict) or not isolated.get("status"):
        return ""
    return f"<p class=\"verdict\">Isolated supervisor authority: {_cell(isolated.get('status'))}</p>"


def _scope_line(record: dict[str, Any], scope: str, label: str) -> str:
    item = (record.get("outcomes") or {}).get(scope) or {}
    verdict = item.get("verdict") or "INCONCLUSIVE"
    if scope == "protected":
        claim = str(item.get("claim_leg") or "")
        if claim and claim in (item.get("legs") or []):
            label = f"Protected execution ({claim})"
    return f"<p class=\"verdict\">{_cell(label)}: {_cell(verdict)}</p>"


def render_html(record: dict[str, Any]) -> str:
    rows = []
    for leg in [*(record.get("comparison") or []), *(record.get("legs") or [])]:
        rows.append(
            "<tr>"
            f"<td>{_cell(leg.get('scope'))}</td>"
            f"<td>{_cell(leg.get('leg_id'))}</td>"
            f"<td>{_cell(leg.get('name'))}</td>"
            f"<td>{_cell(leg.get('verdict'))}</td>"
            f"<td>{_cell(leg.get('decision'))}</td>"
            f"<td>{_cell(leg.get('control_layer'))}</td>"
            f"<td>{_cell(leg.get('before_sha256'))}</td>"
            f"<td>{_cell(leg.get('after_sha256'))}</td>"
            f"<td>{_cell(leg.get('detail'))}</td>"
            "</tr>"
        )
    limits = "".join(f"<li>{_cell(item)}</li>" for item in record.get("coverage_limitations") or [])
    simulated = "".join(f"<li>{_cell(item)}</li>" for item in record.get("simulated") or [])
    basis = _cell(((record.get("outcomes") or {}).get("overall") or {}).get("basis") or "")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Varden assessment {_cell(record.get('run_id'))}</title>
<style>
body {{ font-family: Georgia, serif; background:#161616; color:#e7e1d6; margin:2rem; }}
h1 {{ font-weight:500; }}
table {{ border-collapse:collapse; width:100%; }}
td, th {{ border-bottom:1px solid #333; text-align:left; padding:0.4rem; vertical-align:top; }}
.verdict {{ font-family: ui-monospace, monospace; }}
</style>
</head>
<body>
<p>Varden {_cell(record.get('varden_version'))} · {_cell(record.get('commit'))} · {_cell(record.get('platform'))}</p>
<p>Enforcement mechanism: {_cell(record.get('enforcement_mode'))}</p>
<h1>{_cell(record.get('title'))}</h1>
{_scope_line(record, "baseline", "Baseline execution")}
{_scope_line(record, "protected", "Protected execution")}
{_scope_line(record, "overall", "Overall scenario outcome")}
{_assurance_lines(record)}
{_production_lines(record)}
{_authority_line(record)}
<p>{basis}</p>
<p>{_cell(record.get('business_impact'))}</p>
<p>Objective: {_cell(record.get('objective'))}</p>
<table>
<thead><tr><th>Scope</th><th>Leg</th><th>Step</th><th>Verdict</th><th>Decision</th><th>Layer</th><th>Before</th><th>After</th><th>Detail</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
<h2>Limitations</h2>
<ul>{limits}</ul>
<h2>Simulated</h2>
<ul>{simulated}</ul>
<p>{_cell(record.get('operator_change') or '')}</p>
</body>
</html>
"""


def render_json(record: dict[str, Any]) -> str:
    return json.dumps(record, indent=2, sort_keys=True)
