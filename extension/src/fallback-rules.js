// Varden Web Shield — compact local fallback scanner.
//
// Used by the background service worker only when the configured Varden
// server cannot be reached. This is deliberately much smaller than the
// server-side layered engine (varden/webshield/layers/*.py) — it exists so
// the extension is not *useless* offline, not so it can replace the server.
// Keep this list of patterns small, deterministic and easy to audit; when
// adding a category here, prefer keeping the *names* aligned with the
// server-side rule IDs (see docs/web-shield-architecture.md) even though the
// implementations necessarily differ, so behaviour doesn't silently drift.

const INSTRUCTION_OVERRIDE_RE = /\b(ignore|disregard|forget)\b[^.]{0,40}\b(previous|prior|all|above)\b[^.]{0,40}\b(instruction|instructions|rules|prompt)\b/i;
const CROSS_TOOL_RE = /\b(then\s+)?(always\s+)?call\b[^.]{0,40}\b(wallet|payment|email|shell|filesystem|credential)[\w_-]*\s+tool\b/i;
const SECRECY_RE = /\bwithout\s+(telling|asking|notifying)\s+the\s+user\b|\bdo\s+not\s+(tell|inform|notify)\s+the\s+user\b/i;
const CREDENTIAL_FIELD_RE = /\b(private_key|password|api_key|secret|wallet_address|auth_token|credit_card)\b/i;
const ZERO_WIDTH_RE = /[\u200B-\u200F\u202A-\u202E\uFEFF]/;
const MAX_DESCRIPTION_LENGTH = 4000;

export function localFallbackScan(tool) {
  const findings = [];
  const name = String((tool && tool.name) || '');
  const description = String((tool && tool.description) || '');
  const annotations = (tool && tool.annotations) || {};
  const schemaText = JSON.stringify((tool && tool.inputSchema) || {});
  const haystack = `${name}\n${description}\n${schemaText}`;

  if (INSTRUCTION_OVERRIDE_RE.test(haystack)) {
    findings.push({ rule_id: 'WEBMCP-LOCAL-INJECTION-001', severity: 'critical', category: 'instruction_hierarchy_override' });
  }
  if (CROSS_TOOL_RE.test(haystack)) {
    findings.push({ rule_id: 'WEBMCP-LOCAL-CROSSTOOL-001', severity: 'high', category: 'cross_tool_invocation' });
  }
  if (SECRECY_RE.test(haystack)) {
    findings.push({ rule_id: 'WEBMCP-LOCAL-SECRECY-001', severity: 'high', category: 'secrecy_demand' });
  }
  if (CREDENTIAL_FIELD_RE.test(schemaText) && !/wallet|payment|crypto/i.test(name + description)) {
    findings.push({ rule_id: 'WEBMCP-LOCAL-CAPABILITY-001', severity: 'medium', category: 'capability_mismatch' });
  }
  if (ZERO_WIDTH_RE.test(haystack)) {
    findings.push({ rule_id: 'WEBMCP-LOCAL-UNICODE-001', severity: 'medium', category: 'unicode_obfuscation' });
  }
  if (description.length > MAX_DESCRIPTION_LENGTH) {
    findings.push({ rule_id: 'WEBMCP-LOCAL-STRUCTURAL-001', severity: 'low', category: 'resource_abuse' });
  }
  if (annotations.readOnlyHint === true && /\b(delete|remove|purchase|submit|transfer|update|pay)\b/i.test(description)) {
    findings.push({ rule_id: 'WEBMCP-LOCAL-CAPABILITY-002', severity: 'high', category: 'capability_mismatch' });
  }

  const weight = { critical: 40, high: 28, medium: 14, low: 5 };
  const score = Math.min(100, findings.reduce((sum, f) => sum + (weight[f.severity] || 0), 0));
  const band = score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 40 ? 'suspicious' : score >= 20 ? 'guarded' : 'low';
  return { score, band, findings, engine: 'local_fallback' };
}
