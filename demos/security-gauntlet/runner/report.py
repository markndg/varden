"""JSON and HTML exports. The HTML is a rendering of the same record."""

from __future__ import annotations

import html
import json
from typing import Any


def render_html(record: dict[str, Any]) -> str:
    def cell(value: Any) -> str:
        return html.escape(json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value))

    rows = []
    for leg in record.get("legs") or []:
        rows.append(
            "<tr>"
            f"<td>{cell(leg.get('name'))}</td>"
            f"<td>{cell(leg.get('verdict'))}</td>"
            f"<td>{cell(leg.get('decision'))}</td>"
            f"<td>{cell(leg.get('control_layer'))}</td>"
            f"<td>{cell(leg.get('before_sha256'))}</td>"
            f"<td>{cell(leg.get('after_sha256'))}</td>"
            f"<td>{cell(leg.get('detail'))}</td>"
            "</tr>"
        )
    limits = "".join(f"<li>{cell(item)}</li>" for item in record.get("coverage_limitations") or [])
    simulated = "".join(f"<li>{cell(item)}</li>" for item in record.get("simulated") or [])
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Varden assessment {cell(record.get('run_id'))}</title>
<style>
body {{ font-family: Georgia, serif; background:#161616; color:#e7e1d6; margin:2rem; }}
h1 {{ font-weight:500; }}
table {{ border-collapse:collapse; width:100%; }}
td, th {{ border-bottom:1px solid #333; text-align:left; padding:0.4rem; vertical-align:top; }}
.verdict {{ font-family: ui-monospace, monospace; }}
</style>
</head>
<body>
<p>Varden {cell(record.get('varden_version'))} · {cell(record.get('commit'))} · {cell(record.get('platform'))}</p>
<h1>{cell(record.get('title'))}</h1>
<p class="verdict">{cell(record.get('verdict'))} · {cell(record.get('enforcement_mode'))}</p>
<p>{cell(record.get('business_impact'))}</p>
<p>Objective: {cell(record.get('objective'))}</p>
<table>
<thead><tr><th>Step</th><th>Verdict</th><th>Decision</th><th>Layer</th><th>Before</th><th>After</th><th>Detail</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
<h2>Limitations</h2>
<ul>{limits}</ul>
<h2>Simulated</h2>
<ul>{simulated}</ul>
<p>{cell(record.get('operator_change') or '')}</p>
</body>
</html>
"""


def render_json(record: dict[str, Any]) -> str:
    return json.dumps(record, indent=2, sort_keys=True)
