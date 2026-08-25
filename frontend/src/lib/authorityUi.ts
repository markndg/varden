/** Display helpers for Authority & Provenance UI. Backend remains source of truth. */

export type AttackPathNode = {
  id?: string;
  kind?: string;
  label?: string;
  subtitle?: string;
  trust?: string | null;
  sensitivity?: string | null;
  capability?: string | null;
  edge_to_next?: string | null;
  technical_id?: string | null;
  authority_required?: string[];
  security_relevant?: boolean;
};

export type PathIndex = {
  source?: string | null;
  sink?: string | null;
  route?: string[];
  missing?: string[];
  text?: string;
};

export type IncidentFinding = {
  type?: string;
  label?: string;
  blurb?: string;
  severity?: string;
  explanation?: string;
};

export type Incident = {
  id: string;
  event_id?: number;
  trace_id?: string;
  timestamp?: number;
  agent_name?: string;
  decision?: string;
  display_decision?: string;
  severity?: string;
  title?: string;
  summary?: string;
  tool?: string;
  resource?: string;
  action_type?: string;
  quiet?: boolean;
  sanitiser?: string;
  authority?: {
    required?: string[];
    granted?: string[];
    missing?: string[];
    violation?: boolean;
    escalation?: boolean;
    resource?: string;
    reason?: string;
    required_reasons?: Record<string, string>;
  };
  provenance?: {
    trust?: string;
    complete?: boolean;
    source_types?: string[];
    origins?: string[];
  };
  sources?: any[];
  findings?: IncidentFinding[];
  finding_count?: number;
  finding_types?: string[];
  attack_path?: AttackPathNode[];
  attack_path_full?: AttackPathNode[];
  attack_path_meta?: { truncated?: boolean; shown?: number; total_observed?: number; mode?: string; bound?: number | null };
  attack_path_full_meta?: { truncated?: boolean; shown?: number; total_observed?: number; mode?: string; bound?: number | null };
  attack_path_preview?: string[];
  path_index?: PathIndex;
  why?: string;
  explanation?: {
    summary?: string;
    source_reason?: string;
    required_authority?: string[];
    delegated_authority?: string[];
    missing_authority?: string[];
    required_reasons?: Record<string, string>;
    decision_reason?: string;
    provenance_complete?: boolean;
    outcome?: any;
    text?: string;
  };
  outcome?: {
    enforced?: boolean;
    executed?: boolean | null;
    side_effect_prevented?: boolean | null;
    label?: string;
    detail?: string;
    basis?: string;
  };
  policy?: { matched_rule?: any; reason?: string; action?: string; pack?: string; rule_id?: string };
  side_effect?: string;
  enforcement?: any;
};

const FALLBACK_LABELS: Record<string, string> = {
  confused_deputy: 'Confused deputy',
  untrusted_to_privileged: 'Untrusted source attempted privileged action',
  authority_escalation: 'Authority escalation',
  delegation_violation: 'Missing delegated authority',
  provenance_exfiltration_chain: 'Potential data exfiltration',
  unknown_provenance_sensitive_action: 'Sensitive action with unknown origin',
  cross_server_authority_flow: 'Cross-server authority flow',
};

export function findingLabel(finding: IncidentFinding | string | null | undefined): string {
  if (!finding) return 'Finding';
  if (typeof finding === 'string') {
    return FALLBACK_LABELS[finding] || finding.replace(/_/g, ' ');
  }
  return finding.label || FALLBACK_LABELS[finding.type || ''] || String(finding.type || 'Finding').replace(/_/g, ' ');
}

export function effectiveDecision(incident: { decision?: string | null; display_decision?: string | null } | null | undefined): string {
  return String(incident?.display_decision || incident?.decision || 'allowed').toLowerCase();
}

export function decisionTone(decision?: string | null): 'danger' | 'warn' | 'ok' | 'monitor' {
  const d = String(decision || '').toLowerCase();
  if (d === 'blocked') return 'danger';
  if (d === 'approval_required' || d === 'warned') return 'warn';
  if (d === 'sanitised') return 'ok';
  if (d === 'monitored') return 'monitor';
  return 'ok';
}

export function severityTone(severity?: string | null): 'danger' | 'warn' | 'ok' | 'monitor' {
  const s = String(severity || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'danger';
  if (s === 'medium') return 'warn';
  if (s === 'low') return 'monitor';
  return 'ok';
}

export function decisionLabel(decision?: string | null): string {
  const d = String(decision || 'allowed').toLowerCase();
  if (d === 'blocked') return 'BLOCKED';
  if (d === 'approval_required') return 'APPROVAL REQUIRED';
  if (d === 'warned') return 'WARNED';
  if (d === 'monitored') return 'MONITORED';
  if (d === 'sanitised') return 'SANITISED · ALLOWED';
  return 'ALLOWED';
}

export function trustLabel(trust?: string | null): string {
  if (!trust) return '';
  return String(trust).toUpperCase();
}

export function kindLabel(kind?: string | null): string {
  const k = String(kind || 'node').toLowerCase();
  const map: Record<string, string> = {
    source: 'SOURCE',
    tool_result: 'TOOL RESULT',
    mcp_tool: 'MCP TOOL',
    mcp_server: 'MCP SERVER',
    tool_invocation: 'TOOL INVOCATION',
    web_content: 'WEB CONTENT',
    user_input: 'USER INPUT',
    agent: 'AGENT',
    tool: 'TOOL',
    resource: 'RESOURCE',
    network: 'NETWORK DESTINATION',
    sanitiser: 'SANITISER',
    approval: 'APPROVAL',
    enforcement: 'ENFORCEMENT',
    block: 'BLOCKED',
    allow: 'ALLOWED',
  };
  return map[k] || k.replace(/_/g, ' ').toUpperCase();
}

/** Prefer backend path_index / attack_path_preview — do not re-derive from raw node labels. */
export function pathPreviewText(incident: Incident): string {
  if (incident.path_index?.text) return incident.path_index.text;
  const preview = incident.attack_path_preview || [];
  if (preview.length) return preview.join(' → ');
  return [incident.tool, incident.resource].filter(Boolean).join(' → ');
}

export function pathRouteLabels(incident: Incident): string[] {
  if (incident.path_index?.route?.length) return incident.path_index.route;
  if (incident.attack_path_preview?.length) return incident.attack_path_preview;
  return pathPreviewText(incident).split(' → ').filter(Boolean);
}

export function incidentCountVsFindings(incidents: Incident[]): { incidents: number; findings: number } {
  return {
    incidents: incidents.length,
    findings: incidents.reduce((sum, i) => sum + Number(i.finding_count || i.findings?.length || 0), 0),
  };
}

export function relativeTime(ts?: number | null, now = Date.now() / 1000): string {
  if (!ts) return '';
  const delta = Math.max(0, Math.floor(now - Number(ts)));
  if (delta < 60) return `${delta}s ago`;
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
  return `${Math.floor(delta / 86400)}d ago`;
}

export function formatTs(ts?: number | null): string {
  if (!ts) return '';
  try {
    return new Date(Number(ts) * 1000).toLocaleString();
  } catch {
    return String(ts);
  }
}

export function blockNodeIsClean(node: AttackPathNode | null | undefined): boolean {
  if (!node || (node.kind !== 'block' && node.kind !== 'approval' && node.kind !== 'enforcement')) return true;
  const trust = String(node.trust || '').toLowerCase();
  return trust !== 'hostile' && !node.sensitivity;
}

export function findingChips(findings: IncidentFinding[] | undefined, limit = 3): { visible: string[]; extra: number } {
  const labels = (findings || []).map((f) => findingLabel(f));
  return { visible: labels.slice(0, limit), extra: Math.max(0, labels.length - limit) };
}

export function shouldShowInvestigation(
  tab: string,
  selectedId: string | null | undefined,
  overviewInvestigationOpen: boolean,
): boolean {
  if (!selectedId) return false;
  if (tab === 'coverage' || tab === 'map') return false;
  if (tab === 'overview') return overviewInvestigationOpen;
  return true;
}

export function trustBoundaryLabel(boundary?: string | null): string {
  const b = String(boundary || '').toLowerCase();
  const map: Record<string, string> = {
    untrusted_input: 'UNTRUSTED INPUT',
    delegated_context: 'TRUSTED / DELEGATED',
    privileged_destination: 'PRIVILEGED DESTINATION',
    public_destination: 'PUBLIC DESTINATION',
    sensitive_resource: 'SENSITIVE RESOURCE',
    unknown_destination: 'UNKNOWN DESTINATION',
    capability_domain: 'CAPABILITY DOMAIN',
  };
  return map[b] || (b ? b.replace(/_/g, ' ').toUpperCase() : '');
}
