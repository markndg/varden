import React, { useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

type EventRow = {
  id: number;
  timestamp: number;
  tool?: string;
  agent_name?: string;
  status: string;
  risk_score?: number;
  route_target?: string;
  reason?: string;
  workflow_id?: string | null;
  domain?: string | null;
  classifiers?: Record<string, boolean>;
  trace_id?: string | null;
  decision_latency_ms?: number | null;
};

type TraceSummary = {
  trace_id: string;
  events: any[];
  graph: { nodes: any[]; edges: any[] };
  summary: {
    event_count: number;
    statuses: Record<string, number>;
    tools: Record<string, number>;
    agents: Record<string, number>;
    start_timestamp: number;
    end_timestamp: number;
  };
};

type TraceOption = { trace_id: string; label: string };

type DashboardPayload = {
  metrics: any;
  coverage: any;
  posture: string;
  timeline: any[];
  status_breakdown: Record<string, number>;
  route_breakdown: Record<string, number>;
  top_tools: Array<{ tool: string; count: number }>;
  top_agents: Array<{ agent: string; count: number }>;
  top_domains: Array<{ domain: string; count: number }>;
  http_methods: Array<{ method: string; count: number }>;
  risk_distribution: Record<string, number>;
  classifier_hits: Array<{ classifier: string; count: number }>;
  recent_events: EventRow[];
  recent_alerts: any[];
  latest_risk: any[];
  decision_latency_points: any[];
  scan_performance: any;
  insights: any[];
  recent_traces?: TraceSummary[];
  trace_catalogue?: TraceSummary[];
  alerts?: { items: any[] };
  workflows?: any[];
  jobs?: any[];
  policy_versions?: any[];
  config?: any;
  generated_at?: number;
};

type EventDetail = {
  event: any;
  neighbors: { previous_event_id?: number | null; next_event_id?: number | null };
  workflow_events: any[];
  explainability: any;
  trace?: TraceSummary | null;
};

type PolicyDoc = { block: any[]; warn: any[]; monitor: any[]; allow: any[] };

function pageFromLocation(pathname: string) {
  if (pathname.includes('/ui/rules')) return 'rules';
  if (/\/ui\/decision\/\d+/.test(pathname)) return 'decision';
  return 'overview';
}

function ruleBucketFromSearch(search: string) {
  return new URLSearchParams(search).get('bucket') || '';
}

function ruleFocusTokenFromSearch(search: string) {
  return new URLSearchParams(search).get('focus') || '';
}

function bucketFromStatus(status?: string | null) {
  if (status === 'blocked') return 'block';
  if (status === 'warned') return 'warn';
  if (status === 'allowed') return 'allow';
  if (status === 'monitored') return 'monitor';
  return '';
}

function latencyValueFromPoint(point: any): number | null {
  const value = point?.avg_latency_ms ?? point?.average_latency_ms ?? point?.latency_ms ?? point?.value_ms ?? point?.value ?? point?.avg ?? null;
  const num = Number(value);
  return Number.isFinite(num) ? num : null;
}

function averageLatencyFromPoints(points: any[]): number | null {
  const vals = (points || []).map(latencyValueFromPoint).filter((v): v is number => v !== null);
  if (!vals.length) return null;
  return vals.reduce((a,b)=>a+b,0)/vals.length;
}

function detailIdFromLocation(pathname: string) {
  const match = pathname.match(/\/ui\/decision\/(\d+)/);
  return match ? Number(match[1]) : null;
}

function classNames(...parts: Array<string | false | null | undefined>) {
  return parts.filter(Boolean).join(' ');
}

async function api<T>(path: string, opts: RequestInit = {}, token?: string): Promise<T> {
  const headers = new Headers(opts.headers || {});
  if (token) {
    if (token.includes('.')) headers.set('Authorization', `Bearer ${token}`);
    else headers.set('x-api-key', token);
  }
  if (opts.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const res = await fetch(path, { ...opts, headers });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new Error((data && (data.detail?.detail || data.detail || data.message)) || res.statusText);
  return data as T;
}

function usePersistentState<T>(key: string, fallback: T) {
  const [value, setValue] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch {
      return fallback;
    }
  });
  useEffect(() => {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch {}
  }, [key, value]);
  return [value, setValue] as const;
}

function fmtTs(ts?: number) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleString();
}

function fmtNum(v?: number | null, digits = 0) {
  if (v === undefined || v === null || Number.isNaN(v)) return '0';
  return Number(v).toFixed(digits);
}

function toDateTimeLocalValue(ts?: number | null) {
  if (!ts) return '';
  const dt = new Date(ts * 1000);
  const pad = (v: number) => String(v).padStart(2, '0');
  return `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())}T${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}`;
}

function fromDateTimeLocalValue(value?: string) {
  if (!value) return null;
  const ts = Date.parse(value);
  return Number.isFinite(ts) ? Math.floor(ts / 1000) : null;
}

function isElementFullyVisible(el: Element | null) {
  if (!el) return false;
  const rect = el.getBoundingClientRect();
  const viewportHeight = window.innerHeight || document.documentElement.clientHeight;
  return rect.top >= 0 && rect.bottom <= viewportHeight;
}

function scrollIntoViewIfNeeded(el: Element | null, block: ScrollLogicalPosition = 'start') {
  if (!el || isElementFullyVisible(el)) return;
  el.scrollIntoView({ behavior: 'smooth', block });
}

function formatRuleFieldLabel(field?: string | null) {
  if (!field) return 'condition';
  if (field.startsWith('classifier:')) return `classifier ${field.split(':', 2)[1].replace(/_/g, ' ')}`;
  const normalized = field.startsWith('field:') ? field.slice(6) : field;
  return normalized.replace(/\./g, ' → ').replace(/_/g, ' ');
}

function compactValue(value: any) {
  if (value === undefined || value === null || value === '') return '—';
  if (typeof value === 'string') return value.length > 56 ? `${value.slice(0, 53)}…` : value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.slice(0, 3).map((item) => compactValue(item)).join(', ') + (value.length > 3 ? '…' : '');
  if (typeof value === 'object') {
    const entries = Object.entries(value).slice(0, 3).map(([key, entryValue]) => `${key}=${compactValue(entryValue)}`);
    return entries.join(', ');
  }
  return String(value);
}

function describeMatchedField(row: any): string {
  const field = formatRuleFieldLabel(row?.field);
  const operator = row?.operator;
  if (operator === 'contains') return `${field} contains ${compactValue(row?.expected)}`;
  if (operator === 'in') return `${field} matches ${compactValue(row?.expected)}`;
  if (operator === 'gte') return `${field} ≥ ${compactValue(row?.expected)} (actual ${compactValue(row?.actual)})`;
  if (operator === 'lte') return `${field} ≤ ${compactValue(row?.expected)} (actual ${compactValue(row?.actual)})`;
  if (operator === 'exists') return `${field} ${row?.expected ? 'exists' : 'is absent'}`;
  return `${field} is ${compactValue(row?.expected)}`;
}

function summarizeMatchedFields(rows: any[], max = 3) {
  const items = (rows || []).slice(0, max).map((row) => describeMatchedField(row)).filter(Boolean);
  return items.length ? items.join('; ') : null;
}

function deriveRuleLabelFromRuleObject(matchedRule: any, fallbackStatus?: string): string | null {
  if (!matchedRule) return null;
  if (typeof matchedRule === 'string') return matchedRule;
  const explicit = matchedRule?.title || matchedRule?.name || matchedRule?.description || matchedRule?.reason;
  if (explicit) return explicit;
  const conditions = Object.entries(matchedRule || {})
    .filter(([key]) => !['enabled', 'priority', 'description', 'reason', 'title', 'name'].includes(key))
    .slice(0, 2)
    .map(([key, value]) => {
      if (typeof value === 'object' && value && !Array.isArray(value)) {
        const operator = Object.keys(value as any)[0];
        const expected = (value as any)[operator];
        return describeMatchedField({ field: key, operator, expected });
      }
      return describeMatchedField({ field: key, operator: 'eq', expected: value });
    })
    .filter(Boolean);
  if (conditions.length) return conditions.join(' · ');
  return fallbackStatus ? `${fallbackStatus} policy` : null;
}

function deriveMatchedRuleLabel(event: any): string | null {
  const action = event?.action || event || {};
  const decision = event?.decision || {};
  const matchedRule = event?.matched_rule || decision?.matched_rule;
  const explicitLabel = event?.matched_rule_label
    || deriveRuleLabelFromRuleObject(matchedRule, event?.status || decision?.effective_action || decision?.action)
    || decision?.rule_name
    || decision?.triggered_rule
    || null;
  if (explicitLabel) return explicitLabel;
  const status = event?.status || decision?.effective_action || decision?.action || action?.status || 'allowed';
  if (status === 'blocked' || status === 'warned') {
    return decision?.reason || `${status} policy`;
  }
  return null;
}

function normalizeEventRow(event: any): EventRow & { matched_rule_label?: string | null; parent_event_id?: number | null } {
  const action = event?.action || event || {};
  const decision = event?.decision || {};
  const matchedRuleLabel = deriveMatchedRuleLabel(event);
  return {
    id: Number(event?.id || action?.id || 0),
    timestamp: Number(event?.timestamp || action?.timestamp || 0),
    tool: action?.tool,
    agent_name: action?.agent_name,
    status: event?.status || decision?.effective_action || decision?.action || action?.status || 'allowed',
    risk_score: Number(action?.risk_score || 0),
    route_target: decision?.route_target || action?.route_target,
    reason: decision?.reason,
    workflow_id: event?.workflow_id || null,
    domain: action?.domain || null,
    classifiers: action?.classifiers || {},
    trace_id: event?.trace_id || action?.trace_id || null,
    matched_rule_label: matchedRuleLabel,
    parent_event_id: event?.parent_event_id || action?.parent_event_id || null,
    decision_latency_ms: Number(event?.decision_latency_ms ?? action?.decision_latency_ms ?? decision?.latency_ms ?? decision?.decision_latency_ms ?? 0) || null,
  };
}

function formatRiskReasonLabel(reason?: string) {
  if (!reason) return null;
  const labels: Record<string, string> = {
    tool_call: 'tool invocation observed',
    http_request: 'HTTP call observed',
    llm_call: 'LLM call observed',
    destructive_tool: 'destructive tool usage',
    network_tool: 'network egress tool',
    database_query: 'database/SQL activity',
    suspicious_domain: 'suspicious destination',
    external_domain: 'external destination',
    contains_secrets: 'secrets detected',
    contains_internal_data: 'internal data detected',
    contains_pii: 'PII detected',
    financial_data: 'financial data detected',
    unsafe_keywords: 'unsafe terms detected',
    sql_dangerous: 'dangerous SQL pattern',
    sql_unbounded_write: 'unbounded SQL write',
    sql_privilege_change: 'SQL privilege change',
    sql_schema_enumeration: 'schema enumeration',
    sql_sensitive_table: 'sensitive table access',
    sql_select_star: 'SELECT * query shape',
    sql_missing_limit: 'missing LIMIT on SQL query',
    sql_union_access: 'UNION-based SQL access',
    sql_multi_statement: 'multi-statement SQL',
    sql_comment_obfuscation: 'SQL obfuscation/comment markers',
    sql_suspect: 'suspect SQL structure',
    warned_by_policy: 'warning policy applied',
    blocked_by_policy: 'blocking policy applied',
    repeated_warn_pattern: 'repeated warn pattern',
    repeated_block_pattern: 'repeated block pattern',
    burst_same_tool: 'burst of same tool usage',
    workflow_activity_burst: 'workflow activity burst',
    multi_tool_trace: 'multi-tool trace behaviour',
    multi_domain_trace: 'multi-domain trace behaviour',
    prior_warn_in_trace: 'prior warning already present in trace',
    prior_block_in_trace: 'prior blocking already present in trace',
    suspicious_sequence: 'suspicious multi-step sequence',
  };
  return labels[reason] || reason.replace(/_/g, ' ');
}

function summarizeRiskReasonLabels(reasons?: string[], max = 4) {
  const labels = (reasons || []).map((reason) => formatRiskReasonLabel(reason)).filter(Boolean) as string[];
  return labels.slice(0, max).join(' · ');
}

function eventRoleTone(explainability: any) {
  if (explainability?.inherited_decision_context) return 'muted';
  if ((explainability?.risk_score || 0) > 0) return 'accent';
  return 'muted';
}

function eventRoleDescription(explainability: any) {
  if (explainability?.inherited_decision_context) return 'This step carries forward an earlier warning/block decision and does not add fresh risk on its own.';
  if ((explainability?.risk_score || 0) > 0) return 'This is the scored step that introduced the risk and triggered the visible decision.';
  return 'This is a recorded trace step with no explicit new risk score.';
}


function displayValue(value: any) {
  if (value === undefined || value === null || value === '') return '—';
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value, null, 2);
}

function statusTone(status?: string) {
  if (status === 'blocked') return 'danger';
  if (status === 'warned') return 'warn';
  return 'ok';
}

function ensurePolicyDoc(doc: any): PolicyDoc {
  return {
    block: Array.isArray(doc?.block) ? doc.block : [],
    warn: Array.isArray(doc?.warn) ? doc.warn : [],
    monitor: Array.isArray(doc?.monitor) ? doc.monitor : [],
    allow: Array.isArray(doc?.allow) ? doc.allow : [],
  };
}

function stableStringify(value: any): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  const entries = Object.entries(value).sort(([left], [right]) => left.localeCompare(right));
  return `{${entries.map(([key, entryValue]) => `${JSON.stringify(key)}:${stableStringify(entryValue)}`).join(',')}}`;
}

function ruleFingerprint(rule: any): string {
  return stableStringify(rule || {});
}

function dedupeRules(rules: any[]) {
  const seen = new Set<string>();
  const output: any[] = [];
  for (const rule of rules || []) {
    const fingerprint = ruleFingerprint(rule);
    if (seen.has(fingerprint)) continue;
    seen.add(fingerprint);
    output.push(rule);
  }
  return output;
}

function dedupePolicyDoc(doc: PolicyDoc): PolicyDoc {
  return {
    block: dedupeRules(doc.block),
    warn: dedupeRules(doc.warn),
    monitor: dedupeRules(doc.monitor),
    allow: dedupeRules(doc.allow),
  };
}

function mergePolicyWithoutDuplicates(baseDoc: PolicyDoc, templateDoc: PolicyDoc): PolicyDoc {
  return dedupePolicyDoc({
    block: [...baseDoc.block, ...templateDoc.block],
    warn: [...baseDoc.warn, ...templateDoc.warn],
    monitor: [...baseDoc.monitor, ...templateDoc.monitor],
    allow: [...baseDoc.allow, ...templateDoc.allow],
  });
}

function pickFirstNonEmptyBucket(doc: PolicyDoc): typeof RULE_BUCKETS[number] {
  return RULE_BUCKETS.find((bucket) => (doc[bucket] || []).length > 0) || 'block';
}

const RULE_BUCKETS = ['block', 'warn', 'monitor', 'allow'] as const;
const RULE_TYPES = ['', 'tool_call', 'http_request', 'llm_call'];
const CLASSIFIER_KEYS = ['internal', 'secrets', 'pii', 'financial', 'credit_card', 'source_internal', 'unsafe_keywords'];
const ADVANCED_FIELDS = [
  { key: 'field:url', label: 'URL contains', operator: 'contains', placeholder: '169.254.169.254' },
  { key: 'field:domain', label: 'Domain contains', operator: 'contains', placeholder: 'pastebin or openai.com' },
  { key: 'field:args.args', label: 'Args contain', operator: 'contains', placeholder: 'rm -rf or terraform destroy' },
  { key: 'field:metadata.behavior.suspicious_sequence', label: 'Suspicious sequence', operator: 'eq', valueType: 'boolean' },
  { key: 'field:metadata.behavior.previous_blocked', label: 'Previous blocked step', operator: 'eq', valueType: 'boolean' },
];
const OPERATOR_OPTIONS = ['eq', 'contains', 'startswith', 'endswith', 'exists', 'gte', 'lte', 'in'];

function safeParsePolicy(text: string, fallback: PolicyDoc) {
  try {
    return ensurePolicyDoc(JSON.parse(text));
  } catch {
    return fallback;
  }
}

function setRuleSimpleValue(rule: any, key: string, value: any) {
  const next = { ...rule };
  if (value === '' || value === undefined || value === null) delete next[key];
  else next[key] = value;
  return next;
}

function setRuleOperatorValue(rule: any, key: string, operator: string, rawValue: any) {
  const next = { ...rule };
  const empty = rawValue === '' || rawValue === undefined || rawValue === null;
  if (empty) {
    delete next[key];
    return next;
  }
  if (operator === 'eq' && typeof rawValue !== 'object') next[key] = rawValue;
  else next[key] = { [operator]: rawValue };
  return next;
}

function getRuleOperator(rule: any, key: string, fallback = 'eq') {
  const value = rule?.[key];
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const first = Object.keys(value)[0];
    return first || fallback;
  }
  return fallback;
}

function getRuleValue(rule: any, key: string) {
  const value = rule?.[key];
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const first = Object.keys(value)[0];
    return first ? value[first] : '';
  }
  return value ?? '';
}

function coerceRuleInput(value: string, mode: 'text' | 'number' | 'boolean' | 'list' = 'text') {
  if (mode === 'number') return value === '' ? '' : Number(value);
  if (mode === 'boolean') return value === 'true';
  if (mode === 'list') return value.split(',').map((part) => part.trim()).filter(Boolean);
  return value;
}

function summarizeRule(rule: any) {
  if (!rule) return 'New rule';
  return rule.title || rule.name || rule.description || rule.reason || [rule.type, rule.tool, Object.keys(rule).find((key) => String(key).startsWith('classifier:'))?.replace('classifier:', '')].filter(Boolean).join(' · ') || 'Untitled rule';
}

function customRuleEntries(rule: any) {
  const dedicated = new Set([
    'enabled', 'priority', 'description', 'reason', 'title', 'name', 'type', 'tool',
    'field:url', 'field:domain', 'field:args.args', 'field:risk_score',
    'field:metadata.behavior.suspicious_sequence', 'field:metadata.behavior.previous_blocked',
  ]);
  return Object.entries(rule || {}).filter(([key]) => !dedicated.has(key) && !String(key).startsWith('classifier:'));
}

function Shell() {
  const [token, setToken] = usePersistentState<string>('sentinel.token', '');
  const [page, setPage] = useState<string>(pageFromLocation(location.pathname));
  const [detailId, setDetailId] = useState<number | null>(detailIdFromLocation(location.pathname));
  const [overview, setOverview] = useState<DashboardPayload | null>(null);
  const [detail, setDetail] = useState<EventDetail | null>(null);
  const [policy, setPolicy] = useState<PolicyDoc>(ensurePolicyDoc({}));
  const [policyText, setPolicyText] = useState<string>('');
  const [templates, setTemplates] = useState<any[]>([]);
  const [selectedTraceId, setSelectedTraceId] = useState<string>('');
  const [selectedTrace, setSelectedTrace] = useState<TraceSummary | null>(null);
  const [traceOptions, setTraceOptions] = useState<TraceOption[]>([]);
  const [ruleFocus, setRuleFocus] = useState<string>(new URLSearchParams(location.search).get('rule') || '');
  const [ruleFocusBucket, setRuleFocusBucket] = useState<string>(ruleBucketFromSearch(location.search));
  const [ruleFocusToken, setRuleFocusToken] = useState<string>(ruleFocusTokenFromSearch(location.search));
  const [filters, setFilters] = usePersistentState('sentinel.filters', { search: '', status: 'all', from: '', to: '' });
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const handlePop = () => {
      setPage(pageFromLocation(location.pathname));
      setDetailId(detailIdFromLocation(location.pathname));
      setRuleFocus(new URLSearchParams(location.search).get('rule') || '');
      setRuleFocusBucket(ruleBucketFromSearch(location.search));
      setRuleFocusToken(ruleFocusTokenFromSearch(location.search));
    };
    window.addEventListener('popstate', handlePop);
    return () => window.removeEventListener('popstate', handlePop);
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const payload = await api<any>('/ui/bootstrap');
        if (cancelled) return;
        if (payload?.auth?.token) setToken(payload.auth.token);
        const dashboard = payload?.dashboard || null;
        setOverview(dashboard);
        const initialOptions = Array.from(new Set([
          ...((dashboard?.trace_catalogue || []).map((trace: any) => trace?.trace_id).filter(Boolean)),
          ...((dashboard?.recent_traces || []).map((trace: any) => trace?.trace_id).filter(Boolean)),
          ...((dashboard?.recent_events || []).map((event: any) => event?.trace_id).filter(Boolean)),
        ])).map((traceId: any) => ({ trace_id: String(traceId), label: String(traceId) }));
        setTraceOptions(initialOptions as TraceOption[]);
        const firstTrace = initialOptions[0]?.trace_id || '';
        if (firstTrace) setSelectedTraceId((current) => current || firstTrace);
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to bootstrap UI');
      }
    })();
    return () => { cancelled = true; };
  }, []);

  async function refreshTraceList() {
    if (!token) return [];
    const payload = await api<{ items: TraceSummary[] }>('/traces', {}, token);
    const rows = Array.isArray(payload?.items) ? payload.items : [];
    setTraceOptions(rows.filter((row) => row?.trace_id).map((row) => ({ trace_id: row.trace_id, label: row.trace_id })));
    return rows;
  }

  async function refreshOverview() {
    if (!token) return;
    const [dashboard, traces] = await Promise.all([
      api<DashboardPayload>('/dashboard/overview', {}, token),
      refreshTraceList().catch(() => []),
    ]);
    setOverview(dashboard);
    const firstTrace = selectedTraceId || dashboard?.trace_catalogue?.[0]?.trace_id || dashboard?.recent_traces?.[0]?.trace_id || traces?.[0]?.trace_id || '';
    if (firstTrace) setSelectedTraceId((current) => current || firstTrace);
  }

  async function refreshPolicy() {
    if (!token) return;
    const [doc, tpl] = await Promise.all([
      api<PolicyDoc>('/policy', {}, token),
      api<any>('/policy/templates', {}, token),
    ]);
    const normalized = ensurePolicyDoc(doc);
    setPolicy(normalized);
    setPolicyText(JSON.stringify(normalized, null, 2));
    setTemplates(Array.isArray(tpl) ? tpl : Object.entries(tpl || {}).map(([name, template]) => ({ name, template })));
  }

  async function refreshDetail(id: number) {
    if (!token) return;
    const payload = await api<EventDetail>(`/events/${id}`, {}, token);
    setDetail(payload);
    if (payload?.trace?.trace_id) {
      setSelectedTraceId(payload.trace.trace_id);
      setSelectedTrace(payload.trace);
    }
  }

  useEffect(() => {
    if (!token) return;
    refreshOverview().catch((e: any) => setError(e?.message || 'Failed to refresh overview'));
    if (page === 'rules') refreshPolicy().catch((e: any) => setError(e?.message || 'Failed to load policy'));
    if (page === 'decision' && detailId) refreshDetail(detailId).catch((e: any) => setError(e?.message || 'Failed to load event'));
  }, [token, page, detailId]);

  useEffect(() => {
    if (!token || !selectedTraceId) return;
    let cancelled = false;
    api<TraceSummary>(`/traces/${encodeURIComponent(selectedTraceId)}`, {}, token)
      .then((payload) => { if (!cancelled) setSelectedTrace(payload); })
      .catch(() => { if (!cancelled) setSelectedTrace(null); });
    return () => { cancelled = true; };
  }, [token, selectedTraceId]);

  useEffect(() => {
    if (!token) return;
    const stream = new EventSource(`/stream/updates?token=${encodeURIComponent(token)}`);
    stream.onmessage = (evt) => {
      try {
        const message = JSON.parse(evt.data || '{}');
        if (message?.type === 'event') {
          refreshOverview().catch(() => {});
          if (page === 'decision' && detailId) refreshDetail(detailId).catch(() => {});
        }
        if (message?.type === 'config' && message?.key === 'scan_mode') {
          setOverview((prev) => prev ? ({ ...prev, config: { ...(prev.config || {}), scan_mode: message.value } }) : prev);
        }
      } catch {}
    };
    return () => stream.close();
  }, [token, page, detailId]);

  function navigate(next: string, path: string) {
    history.pushState({}, '', path);
    setPage(next);
    setDetailId(detailIdFromLocation(path));
    const search = '?' + (path.split('?')[1] || '');
    setRuleFocus(new URLSearchParams(path.split('?')[1] || '').get('rule') || '');
    setRuleFocusBucket(ruleBucketFromSearch(search));
    setRuleFocusToken(ruleFocusTokenFromSearch(search));
  }

  function buildRuleNavigationPath(label: string, bucket?: string, matchedRule?: any) {
    const params = new URLSearchParams();
    params.set('rule', label);
    if (bucket) params.set('bucket', bucket);
    params.set('focus', matchedRule ? ruleFingerprint(matchedRule) : `${label}:${Date.now()}`);
    return `/ui/rules?${params.toString()}`;
  }

  async function savePolicy() {
    if (!token) return;
    setLoading(true);
    setError('');
    setNotice('');
    try {
      const parsed = dedupePolicyDoc(ensurePolicyDoc(JSON.parse(policyText)));
      setPolicyText(JSON.stringify(parsed, null, 2));
      await api('/policy/validate', { method: 'POST', body: JSON.stringify(parsed) }, token);
      await api('/policy', { method: 'PUT', body: JSON.stringify(parsed) }, token);
      setPolicy(parsed);
      setNotice('Policy saved');
      await refreshPolicy();
    } catch (e: any) {
      setError(e?.message || 'Failed to save policy');
    } finally {
      setLoading(false);
    }
  }

  async function setScanMode(mode: string) {
    if (!token) return;
    try {
      await api('/runtime/config/scan-mode', { method: 'POST', body: JSON.stringify({ scan_mode: mode }) }, token);
      setOverview((prev) => prev ? ({ ...prev, config: { ...(prev.config || {}), scan_mode: mode } }) : prev);
      setNotice(`Scan mode switched to ${mode}`);
    } catch (e: any) {
      setError(e?.message || 'Failed to update scan mode');
    }
  }

  const filteredEvents = useMemo(() => {
    const rows = overview?.recent_events || [];
    return rows.filter((row) => {
      if (filters.status !== 'all' && row.status !== filters.status) return false;
      if (filters.search) {
        const blob = JSON.stringify(row).toLowerCase();
        if (!blob.includes(filters.search.toLowerCase())) return false;
      }
      const fromTs = fromDateTimeLocalValue((filters as any).from);
      const toTs = fromDateTimeLocalValue((filters as any).to);
      if (fromTs && Number(row.timestamp || 0) < fromTs) return false;
      if (toTs && Number(row.timestamp || 0) > toTs) return false;
      return true;
    });
  }, [overview, filters]);

  const traceCandidates = useMemo(() => {
    const ids = new Set<string>();
    const out: TraceOption[] = [];
    for (const trace of traceOptions) {
      if (trace?.trace_id && !ids.has(trace.trace_id)) {
        ids.add(trace.trace_id);
        out.push(trace);
      }
    }
    for (const trace of [
      ...((overview as any)?.trace_catalogue || []),
      ...(overview?.recent_traces || []),
    ]) {
      if (trace?.trace_id && !ids.has(trace.trace_id)) {
        ids.add(trace.trace_id);
        out.push({ trace_id: trace.trace_id, label: trace.trace_id });
      }
    }
    for (const event of overview?.recent_events || []) {
      const traceId = (event as any).trace_id || '';
      if (traceId && !ids.has(traceId)) {
        ids.add(traceId);
        out.push({ trace_id: traceId, label: traceId });
      }
    }
    if (selectedTrace?.trace_id && !ids.has(selectedTrace.trace_id)) {
      out.unshift({ trace_id: selectedTrace.trace_id, label: selectedTrace.trace_id });
    }
    return out;
  }, [overview, traceOptions, selectedTrace?.trace_id]);

  const currentScanMode = overview?.config?.scan_mode || 'deep';

  return (
    <div className="shell">
      <div className="shell__bg shell__bg--one" />
      <div className="shell__bg shell__bg--two" />
      <aside className="sidebar">
        <div className="brand">
          <div className="brand__markWrap">
            <img src="/static/assets/sentinel-icon.png" alt="Arbiter mark" className="brand__icon" />
            <span className="brand__pulse" aria-hidden="true" />
          </div>
          <div className="brand__copy">
            <div className="brand__eyebrow">Agent governance</div>
            <div className="brand__title">Arbiter</div>
            <div className="brand__subtitle">Command Center</div>
          </div>
        </div>
        <nav className="nav">
          <button className={classNames('nav__item', page === 'overview' && 'is-active')} onClick={() => navigate('overview', '/ui')}>Overview</button>
          <button className={classNames('nav__item', page === 'rules' && 'is-active')} onClick={() => navigate('rules', '/ui/rules')}>Rules Workspace</button>
          {detailId ? <button className={classNames('nav__item', page === 'decision' && 'is-active')} onClick={() => navigate('decision', `/ui/decision/${detailId}`)}>Decision View</button> : null}
        </nav>
        <div className="sidebar__section">
          <div className="sidebar__label">Inspection mode</div>
          <div className="toggleRow">
            {['deep', 'fast'].map((mode) => (
              <button key={mode} className={classNames('segmented', currentScanMode === mode && 'is-active')} onClick={() => setScanMode(mode)}>{mode}</button>
            ))}
          </div>
          <p className="muted">{overview?.config?.notes?.[currentScanMode] || 'Live policy inspection for agent actions.'}</p>
        </div>
        <div className="sidebar__section sidebar__section--grow">
          <div className="sidebar__label">Operational highlights</div>
          {!traceCandidates.length ? <div className="emptyState emptyState--compact"><strong>No traces recorded yet.</strong><span className="muted">Run the OSS demo to seed trace data for the flow explorer and trace catalogue.</span></div> : null}
          {!traceCandidates.length ? <button className="button" onClick={() => { if (page !== 'overview') navigate('overview', '/ui'); setNotice('Generating OSS demo traces…'); (async () => { if (!token) return; try { const payload = await api<any>('/demo/run', { method: 'POST', body: '{}' }, token); setOverview(payload.dashboard); const firstTrace = payload.dashboard?.recent_traces?.[0]?.trace_id || payload.dashboard?.trace_catalogue?.[0]?.trace_id || ''; if (firstTrace) setSelectedTraceId(firstTrace); setNotice('OSS demo seeded with allow, warn, and block traces'); } catch (e: any) { setError(e?.message || 'Failed to run demo'); } })(); }}>Generate demo traces</button> : null}
          <div className="chipGrid">
            {(overview?.insights || []).slice(0, 3).map((insight, idx) => (
              <div key={idx} className={classNames('chip', insight.severity === 'high' && 'chip--danger', insight.severity === 'medium' && 'chip--warn')}>
                <strong>{insight.title}</strong>
                <span>{insight.message}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="sidebar__footer">
          <input className="input" value={token} onChange={(e) => setToken(e.target.value)} placeholder="API key or bearer token" />
          <button className="button button--ghost" onClick={() => refreshOverview().catch((e:any)=>setError(e?.message||'Refresh failed'))}>Refresh snapshot</button>
        </div>
      </aside>

      <main className="main">
        <header className="topbar card">
          <div>
            <div className="eyebrow">Live operations</div>
            <h1>{page === 'rules' ? 'Policy workspace' : page === 'decision' ? 'Decision drilldown' : 'Trace and flow mission control'}</h1>
            <p className="muted">See what the agent attempted, why Arbiter scored it the way it did, and how policy changed the outcome.</p>
          </div>
          <div className="topbar__actions">
            <div className="statusPill">Posture: <strong>{overview?.posture || 'loading'}</strong></div>
            <div className="statusPill">Events: <strong>{overview?.metrics?.total_events ?? 0}</strong></div>
            <div className="statusPill">P95: <strong>{fmtNum(overview?.metrics?.p95_decision_latency_ms, 1)} ms</strong></div>
          </div>
        </header>

        {error ? <div className="banner banner--error">{error}</div> : null}
        {notice ? <div className="banner banner--ok">{notice}</div> : null}

        {page === 'overview' && overview ? (
          <OverviewPage
            overview={overview}
            filteredEvents={filteredEvents}
            filters={filters}
            setFilters={setFilters}
            selectedTrace={selectedTrace}
            setSelectedTraceId={setSelectedTraceId}
            token={token}
            traceCandidates={traceCandidates}
            onRunDemo={async () => { if (!token) return; try { const payload = await api<any>('/demo/run', { method: 'POST', body: '{}' }, token); setOverview(payload.dashboard); const traces = await refreshTraceList().catch(() => []); const firstTrace = payload.dashboard?.trace_catalogue?.[0]?.trace_id || payload.dashboard?.recent_traces?.[0]?.trace_id || traces?.[0]?.trace_id || ''; if (firstTrace) setSelectedTraceId(firstTrace); setNotice('OSS demo seeded with allow, warn, and block traces'); } catch (e: any) { setError(e?.message || 'Failed to run demo'); } }}
            onOpenDecision={(id) => navigate('decision', `/ui/decision/${id}`)}
          />
        ) : null}

        {page === 'rules' ? (
          <RulesPage
            policy={policy}
            policyText={policyText}
            setPolicyText={setPolicyText}
            templates={templates}
            onApplyTemplate={(template) => {
              const merged = ensurePolicyDoc(template?.template || template || {});
              setPolicyText(JSON.stringify(merged, null, 2));
            }}
            onSave={savePolicy}
            loading={loading}
            ruleFocus={ruleFocus}
            ruleFocusBucket={ruleFocusBucket}
            ruleFocusToken={ruleFocusToken}
          />
        ) : null}

        {page === 'decision' && detail ? (
          <DecisionPage
            detail={detail}
            onOpenDecision={(id) => navigate('decision', `/ui/decision/${id}`)}
            onOpenRule={(label: string, bucket?: string, matchedRule?: any) => navigate('rules', buildRuleNavigationPath(label, bucket, matchedRule))}
          />
        ) : null}
      </main>
    </div>
  );
}

function OverviewPage({ overview, filteredEvents, filters, setFilters, selectedTrace, setSelectedTraceId, onOpenDecision, token, onRunDemo, traceCandidates }: any) {
  const [signalView, setSignalView] = useState<'timeline' | 'sankey'>('sankey');
  const [selectedBucketTs, setSelectedBucketTs] = useState<number | null>(null);
  const [selectedAlertMode, setSelectedAlertMode] = useState<'all' | 'open'>('all');
  const [focusedEventIds, setFocusedEventIds] = useState<number[] | null>(null);
  const [focusLabel, setFocusLabel] = useState<string>('');
  const [replayIndex, setReplayIndex] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [sankeyMode, setSankeyMode] = useState<'agent_tool_outcome' | 'agent_rule_outcome' | 'tool_rule_outcome'>('agent_tool_outcome');
  const [simulationDraft, setSimulationDraft] = useState<string>(JSON.stringify({ warn: [{ "field:risk_score": { "gte": 50 } }], block: [], monitor: [], allow: [] }, null, 2));
  const [simulationResult, setSimulationResult] = useState<any>(null);
  const [simulating, setSimulating] = useState(false);
  const activityRef = useRef<HTMLElement | null>(null);
  const alertsRef = useRef<HTMLElement | null>(null);

  const sourceEvents = useMemo(() => {
    const merged = new Map<number, EventRow>();
    for (const row of (overview.recent_events || []).map(normalizeEventRow)) {
      if (row.id) merged.set(row.id, row);
    }
    for (const trace of (overview.recent_traces || [])) {
      for (const row of (trace.events || []).map(normalizeEventRow)) {
        if (row.id) merged.set(row.id, { ...(merged.get(row.id) || {}), ...row });
      }
    }
    return Array.from(merged.values()).sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
  }, [overview.recent_traces, overview.recent_events]);

  const replayEvents = useMemo(() => ((selectedTrace?.events || []).map(normalizeEventRow).sort((a: EventRow, b: EventRow) => (a.timestamp || 0) - (b.timestamp || 0))), [selectedTrace]);

  useEffect(() => {
    if (!isPlaying || !replayEvents.length) return;
    const handle = window.setInterval(() => {
      setReplayIndex((current) => {
        if (current >= replayEvents.length - 1) {
          setIsPlaying(false);
          return current;
        }
        return current + 1;
      });
    }, 900);
    return () => window.clearInterval(handle);
  }, [isPlaying, replayEvents.length]);

  useEffect(() => {
    setReplayIndex(0);
    setIsPlaying(false);
  }, [selectedTrace?.trace_id]);

  const visibleReplayEvents = useMemo(() => replayEvents.slice(0, Math.max(1, replayIndex + 1)), [replayEvents, replayIndex]);

  const timelinePoints = useMemo(() => {
    const buckets = new Map<number, { timestamp: number; blocked: number; warned: number; allowed: number; eventIds: number[]; latencyValues: number[]; avg_latency_ms: number | null }>();
    for (const event of sourceEvents) {
      const bucketStart = Math.floor(Number(event.timestamp || 0) / 60) * 60;
      const bucket = buckets.get(bucketStart) || { timestamp: bucketStart, blocked: 0, warned: 0, allowed: 0, eventIds: [], latencyValues: [], avg_latency_ms: null };
      if (event.status === 'blocked') bucket.blocked += 1;
      else if (event.status === 'warned') bucket.warned += 1;
      else bucket.allowed += 1;
      bucket.eventIds.push(event.id);
      const latency = Number((event as any).decision_latency_ms || 0);
      if (Number.isFinite(latency) && latency > 0) bucket.latencyValues.push(latency);
      buckets.set(bucketStart, bucket);
    }
    const externalLatency = new Map<number, number>();
    for (const point of (overview?.decision_latency_points || [])) {
      const ts = Math.floor(Number(point?.timestamp || 0) / 60) * 60;
      const latency = latencyValueFromPoint(point);
      if (ts && latency !== null) externalLatency.set(ts, latency);
    }
    return Array.from(buckets.values()).map((bucket) => ({
      ...bucket,
      avg_latency_ms: bucket.latencyValues.length
        ? bucket.latencyValues.reduce((sum, value) => sum + value, 0) / bucket.latencyValues.length
        : (externalLatency.get(bucket.timestamp) ?? null),
    })).sort((a, b) => a.timestamp - b.timestamp);
  }, [sourceEvents, overview?.decision_latency_points]);

  const scopedEvents = useMemo(() => {
    let rows = sourceEvents;
    const fromTs = fromDateTimeLocalValue(filters.from);
    const toTs = fromDateTimeLocalValue(filters.to);
    if (fromTs) rows = rows.filter((event: EventRow) => Number(event.timestamp || 0) >= fromTs);
    if (toTs) rows = rows.filter((event: EventRow) => Number(event.timestamp || 0) <= toTs);
    if (selectedBucketTs) {
      const bucketStart = Math.floor(selectedBucketTs / 60) * 60;
      rows = rows.filter((event: EventRow) => Math.floor((event.timestamp || 0) / 60) * 60 === bucketStart);
    }
    if (focusedEventIds?.length) {
      const idSet = new Set(focusedEventIds);
      rows = rows.filter((event: EventRow) => idSet.has(event.id));
    }
    if (filters.status !== 'all') rows = rows.filter((row: EventRow) => row.status === filters.status);
    if (filters.search) {
      const term = filters.search.toLowerCase();
      rows = rows.filter((row: EventRow) => JSON.stringify(row).toLowerCase().includes(term));
    }
    return rows.sort((a: EventRow, b: EventRow) => (b.timestamp || 0) - (a.timestamp || 0));
  }, [sourceEvents, selectedBucketTs, focusedEventIds, filters]);

  const visibleAlerts = useMemo(() => {
    const items = overview.alerts?.items || overview.recent_alerts || [];
    if (selectedAlertMode === 'open') return items.filter((alert: any) => !alert.acknowledged);
    return items;
  }, [overview.alerts, overview.recent_alerts, selectedAlertMode]);

  const selectedBucket = useMemo(() => timelinePoints.find((point: any) => point.timestamp === selectedBucketTs) || null, [timelinePoints, selectedBucketTs]);

  const riskStories = useMemo(() => {
    const stories: Array<{title: string; message: string; severity: string; eventIds: number[]}> = [];
    const byAgent = new Map<string, EventRow[]>();
    const byRule = new Map<string, EventRow[]>();
    for (const event of sourceEvents) {
      const agent = event.agent_name || 'unknown';
      byAgent.set(agent, [...(byAgent.get(agent) || []), event]);
      if ((event as any).matched_rule_label) {
        const label = (event as any).matched_rule_label as string;
        byRule.set(label, [...(byRule.get(label) || []), event]);
      }
    }
    for (const [agent, rows] of byAgent.entries()) {
      const warned = rows.filter((row) => row.status === 'warned');
      if (warned.length >= 2) stories.push({ title: `Repeated warn pattern · ${agent}`, message: `${warned.length} warned actions from the same agent in the current window.`, severity: warned.length >= 3 ? 'high' : 'medium', eventIds: warned.map((row) => row.id) });
    }
    for (const [rule, rows] of byRule.entries()) {
      if (rows.length >= 2) stories.push({ title: `Rule firing repeatedly · ${rule}`, message: `${rows.length} actions triggered the same rule, which may justify a more explicit policy or route.`, severity: rows.some((row) => row.status === 'blocked') ? 'high' : 'medium', eventIds: rows.map((row) => row.id) });
    }
    const risky = sourceEvents.filter((row) => (row.risk_score || 0) >= 70);
    if (risky.length) stories.push({ title: 'High-severity chain activity', message: `${risky.length} actions are currently above risk score 70.`, severity: 'high', eventIds: risky.map((row) => row.id) });
    return stories.slice(0, 4);
  }, [sourceEvents]);

  const traceCatalogue = useMemo(() => {
    const rows: TraceSummary[] = [];
    const seen = new Set<string>();
    for (const trace of ([...(overview.trace_catalogue || []), ...(overview.recent_traces || []), ...(selectedTrace ? [selectedTrace] : [])] as TraceSummary[])) {
      if (trace?.trace_id && !seen.has(trace.trace_id)) {
        seen.add(trace.trace_id);
        rows.push(trace);
      }
    }
    return rows;
  }, [overview.trace_catalogue, overview.recent_traces, selectedTrace]);

  const hasTraceData = !!(traceCandidates?.length || traceCatalogue.length || selectedTrace?.trace_id);

  function focusActivity(nextStatus: string, nextSearch = '', eventIds: number[] | null = null, label = '', scrollToPanel = true) {
    setFilters({ ...filters, status: nextStatus, search: nextSearch });
    setSelectedBucketTs(null);
    setFocusedEventIds(eventIds && eventIds.length ? Array.from(new Set(eventIds)) : null);
    setFocusLabel(label);
    if (scrollToPanel) requestAnimationFrame(() => scrollIntoViewIfNeeded(activityRef.current, 'start'));
  }

  function focusAlerts(mode: 'all' | 'open' = 'open', scrollToPanel = true) {
    setSelectedAlertMode(mode);
    if (scrollToPanel) requestAnimationFrame(() => scrollIntoViewIfNeeded(alertsRef.current, 'start'));
  }

  function clearFocus() {
    setSelectedBucketTs(null);
    setFocusedEventIds(null);
    setFocusLabel('');
    setFilters({ ...filters, search: '', status: 'all', from: '', to: '' });
  }

  async function runSimulation() {
    if (!token || !selectedTrace?.trace_id) return;
    setSimulating(true);
    try {
      const candidate = ensurePolicyDoc(JSON.parse(simulationDraft));
      const result = await api<any>(`/policy/simulate?trace_id=${encodeURIComponent(selectedTrace.trace_id)}`, { method: 'POST', body: JSON.stringify(candidate) }, token);
      setSimulationResult(result);
    } finally {
      setSimulating(false);
    }
  }

  const replayTrace = selectedTrace ? {
    ...selectedTrace,
    events: (selectedTrace.events || []).filter((evt: any) => visibleReplayEvents.some((row: EventRow) => row.id === evt.id)),
    graph: {
      ...selectedTrace.graph,
      nodes: (selectedTrace.graph?.nodes || []).filter((node: any) => visibleReplayEvents.some((row: EventRow) => row.id === node.id)),
      edges: (selectedTrace.graph?.edges || []).filter((edge: any) => visibleReplayEvents.some((row: EventRow) => row.id === edge.source) && visibleReplayEvents.some((row: EventRow) => row.id === edge.target)),
    },
  } : selectedTrace;

  return (
    <div className="pageGrid">
      <section className="metricsRow">
        <MetricCard title="Blocked" value={sourceEvents.filter((event: EventRow) => event.status === 'blocked').length} subtitle="Current activity window" tone="danger" onClick={() => focusActivity('blocked', '', sourceEvents.filter((event: EventRow) => event.status === 'blocked').map((event: EventRow) => event.id), 'Blocked events')} />
        <MetricCard title="Warned" value={sourceEvents.filter((event: EventRow) => event.status === 'warned').length} subtitle="Current activity window" tone="warn" onClick={() => focusActivity('warned', '', sourceEvents.filter((event: EventRow) => event.status === 'warned').map((event: EventRow) => event.id), 'Warned events')} />
        <MetricCard title="Allowed" value={sourceEvents.filter((event: EventRow) => event.status === 'allowed').length} subtitle="Current activity window" tone="ok" onClick={() => focusActivity('allowed', '', sourceEvents.filter((event: EventRow) => event.status === 'allowed').map((event: EventRow) => event.id), 'Allowed events')} />
        <MetricCard title="Avg latency" value={`${fmtNum(overview.metrics?.avg_decision_latency_ms ?? averageLatencyFromPoints(overview.decision_latency_points || []), 1)} ms`} subtitle="Decision average in current window" onClick={() => { setSignalView('timeline'); requestAnimationFrame(() => scrollIntoViewIfNeeded(activityRef.current?.previousElementSibling as Element | null, 'start')); }} />
      </section>

      <section className="layout layout--topOverview">
        <div className="card card--signalHero">
          <div className="sectionHeader"><div><div className="eyebrow">Signal trends</div><h3>Risk and timeline</h3></div><div className="toggleRow"><button className={classNames('segmented', signalView === 'timeline' && 'is-active')} onClick={() => setSignalView('timeline')}>Timeline</button><button className={classNames('segmented', signalView === 'sankey' && 'is-active')} onClick={() => setSignalView('sankey')}>Sankey</button></div></div>
          {signalView === 'timeline' ? <><MiniTimeline data={timelinePoints} selectedTimestamp={selectedBucketTs} sourceEvents={sourceEvents} onSelectBucket={(ts: number | null, eventIds?: number[]) => { setSelectedBucketTs((current) => current === ts ? null : ts); setFocusedEventIds(eventIds && eventIds.length ? eventIds : null); setFocusLabel(ts ? `Timeline focus · ${eventIds?.length || 0} linked events` : ''); requestAnimationFrame(() => scrollIntoViewIfNeeded(activityRef.current, 'start')); }} /><div className="signalLegend"><span><i className="legendSwatch legendSwatch--danger" />Blocked</span><span><i className="legendSwatch legendSwatch--warn" />Warned</span><span><i className="legendSwatch legendSwatch--ok" />Allowed</span><span><i className="legendSwatch legendSwatch--severity" />Severity-weighted height</span><span><i className="legendSwatch legendSwatch--latency" />Latency marker</span></div>{selectedBucket ? <div className="focusSummary"><strong>{fmtTs(selectedBucket.timestamp)}</strong><span>{selectedBucket.blocked || 0} blocked · {selectedBucket.warned || 0} warned · {selectedBucket.allowed || 0} allowed · {scopedEvents.length} linked events{selectedBucket.avg_latency_ms ? ` · avg latency ${fmtNum(selectedBucket.avg_latency_ms, 1)} ms` : ''}</span></div> : null}</> : <><div className="toggleRow sankeyModes"><button className={classNames('segmented', sankeyMode === 'agent_tool_outcome' && 'is-active')} onClick={() => setSankeyMode('agent_tool_outcome')}>Agent → Tool → Outcome</button><button className={classNames('segmented', sankeyMode === 'agent_rule_outcome' && 'is-active')} onClick={() => setSankeyMode('agent_rule_outcome')}>Agent → Rule → Outcome</button><button className={classNames('segmented', sankeyMode === 'tool_rule_outcome' && 'is-active')} onClick={() => setSankeyMode('tool_rule_outcome')}>Tool → Rule → Outcome</button></div><SankeyPanel overview={overview} sourceEvents={sourceEvents} mode={sankeyMode} onFocus={(opts: any) => focusActivity(opts.status || 'all', opts.search || '', opts.eventIds || null, opts.label || 'Sankey focus')} /></>}
          <div className="twoColStats"><MiniBarList title="Top tools" items={(overview.top_tools || []).map((item: any) => ({ label: item.tool, value: item.count }))} /><MiniBarList title="Classifier hits" items={(overview.classifier_hits || []).map((item: any) => ({ label: item.classifier, value: item.count }))} /></div>
        </div>

        <div className="card card--riskPanel">
          <div className="sectionHeader"><div><div className="eyebrow">Risk story</div><h3>Top risk patterns</h3></div></div>
          <div className="insightList scrollPanel scrollPanel--medium scrollPanel--fill">
            {riskStories.map((story, idx) => (
              <button key={idx} className={classNames('insight', story.severity === 'high' && 'is-danger', story.severity === 'medium' && 'is-warn')} onClick={() => focusActivity('all', '', story.eventIds, story.title)}>
                <strong>{story.title}</strong><div className="muted">{story.message}</div>
              </button>
            ))}
            {!riskStories.length ? <div className="emptyState"><strong>No notable risk stories yet.</strong><span className="muted">Run the OSS demo to seed a full allow / warn / block flow.</span></div> : null}
          </div>
        </div>
      </section>

      <section className="layout layout--equalCols">
        <div className="card card--stretch card--matchedScroll" ref={activityRef as any}>
          <div className="sectionHeader">
            <div><div className="eyebrow">Live rail</div><h3>Recent activity</h3></div>
            <div className="filters filters--wrap">
              <input className="input" placeholder="Search tool, agent, domain" value={filters.search} onChange={(e) => setFilters({ ...filters, search: e.target.value })} />
              <select className="input input--small" value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}><option value="all">All</option><option value="allowed">Allowed</option><option value="warned">Warned</option><option value="blocked">Blocked</option></select>
              <input className="input input--small" type="datetime-local" step="1" value={filters.from || ''} onChange={(e) => setFilters({ ...filters, from: e.target.value })} />
              <input className="input input--small" type="datetime-local" step="1" value={filters.to || ''} onChange={(e) => setFilters({ ...filters, to: e.target.value })} />
              <button className="button button--ghost" onClick={() => { const now = Math.floor(Date.now() / 1000); setFilters({ ...filters, from: toDateTimeLocalValue(now - 3600), to: toDateTimeLocalValue(now) }); }}>Last hour</button>
              <button className="button button--ghost" onClick={() => { const now = Math.floor(Date.now() / 1000); setFilters({ ...filters, from: toDateTimeLocalValue(now - 86400), to: toDateTimeLocalValue(now) }); }}>Last 24h</button>
            </div>
          </div>
          {(selectedBucket || filters.status !== 'all' || filters.search || filters.from || filters.to || focusedEventIds?.length || focusLabel) ? <div className="activeFilterBar"><div className="traceSummaryBar">{selectedBucket ? <span>Focused minute: {fmtTs(selectedBucket.timestamp)}</span> : null}{focusLabel ? <span>{focusLabel}</span> : null}{filters.status !== 'all' ? <span>Status: {filters.status}</span> : null}{filters.search ? <span>Search: {filters.search}</span> : null}{filters.from ? <span>From: {filters.from}</span> : null}{filters.to ? <span>To: {filters.to}</span> : null}<span>{scopedEvents.length} events in current focus</span></div><button className="button button--ghost" onClick={clearFocus}>Clear focus</button></div> : null}
          <div className="eventRail scrollPanel scrollPanel--rail">{scopedEvents.length ? scopedEvents.map((event: any) => (<button key={event.id} className="eventRow" onClick={() => { if (event.trace_id) setSelectedTraceId(event.trace_id); onOpenDecision(event.id); }}><div className={classNames('eventRow__dot', `is-${statusTone(event.status)}`)} /><div className="eventRow__main"><div className="eventRow__title">{event.tool || 'unknown'} <span className={`badge badge--${statusTone(event.status)}`}>{event.status}</span>{event.matched_rule_label ? <span className="badge badge--rule">{event.matched_rule_label}</span> : null}</div><div className="eventRow__meta">{event.agent_name || 'unknown agent'} · {event.domain || event.route_target || 'no route'} · {fmtTs(event.timestamp)}</div></div><div className="eventRow__score">{Math.round(event.risk_score || 0)}</div></button>)) : <div className="emptyState"><strong>No events match the current focus.</strong><span className="muted">Try clearing the timeline focus or using a broader status filter.</span></div>}</div>
        </div>

        <div className="card card--stretch card--matchedScroll" ref={alertsRef as any}>
          <div className="sectionHeader"><div><div className="eyebrow">Response</div><h3>Insights and alerts</h3></div><div className="toggleRow"><button className={classNames('segmented', selectedAlertMode === 'all' && 'is-active')} onClick={() => focusAlerts('all')}>All alerts</button><button className={classNames('segmented', selectedAlertMode === 'open' && 'is-active')} onClick={() => focusAlerts('open')}>Open only</button></div></div>
          <div className="insightList scrollPanel scrollPanel--rail scrollPanel--fill">{(overview.insights || []).map((insight: any, idx: number) => (<div key={idx} className={classNames('insight', insight.severity === 'high' && 'is-danger', insight.severity === 'medium' && 'is-warn')}><strong>{insight.title}</strong><div className="muted">{insight.message}</div></div>))}{visibleAlerts.map((alert: any, idx: number) => (<button key={alert.id || idx} className={classNames('alertItem', !alert.acknowledged && 'alertItem--open')} onClick={() => alert.event_id ? onOpenDecision(alert.event_id) : undefined}><div><div className="alertItem__title">{alert.title || 'Alert'}</div><div className="alertItem__meta">{alert.message || 'No message'} · {alert.severity || 'info'}</div></div><div className={`badge badge--${alert.severity === 'high' ? 'danger' : alert.severity === 'medium' ? 'warn' : 'ok'}`}>{alert.acknowledged ? 'acknowledged' : 'open'}</div></button>))}</div>
        </div>
      </section>

      <section className="stack">
        <section className="card card--hero">
          <div className="hero__left">
            <div className="eyebrow">Command view</div>
            <h2>Execution flow explorer</h2>
            <p className="muted">Run the built-in OSS demo, replay a trace, and inspect the exact rule fields that fired.</p>
            {!hasTraceData ? <div className="emptyState"><strong>No trace data yet.</strong><span className="muted">Run the OSS demo to generate traces and unlock the replay explorer.</span></div> : null}
            <div className="commandTracePicker">
              <div className="sidebar__label">Trace focus</div>
              <select className="input" value={selectedTrace?.trace_id || ''} onChange={(e) => setSelectedTraceId(e.target.value)} disabled={!traceCandidates.length}>
                <option value="">{traceCandidates.length ? 'Select recent trace' : 'No traces yet'}</option>
                {traceCandidates.map((trace: any) => <option key={trace.trace_id} value={trace.trace_id}>{trace.label}</option>)}
              </select>
            </div>
            <div className="hero__stats">
              <Stat label="Trace events" value={selectedTrace?.summary?.event_count || 0} />
              <Stat label="Agents" value={Object.keys(selectedTrace?.summary?.agents || {}).length} />
              <Stat label="Tools" value={Object.keys(selectedTrace?.summary?.tools || {}).length} />
              <Stat label="Duration" value={selectedTrace?.summary ? `${Math.max(0, Math.round((selectedTrace.summary.end_timestamp - selectedTrace.summary.start_timestamp) * 1000))} ms` : '—'} />
            </div>
            <div className="toggleRow replayToolbar">
              <button className="button" onClick={onRunDemo}>Run OSS demo</button>
              <button className="button button--ghost" onClick={() => setIsPlaying((v) => !v)} disabled={!replayEvents.length}>{isPlaying ? 'Pause replay' : 'Play replay'}</button>
              <button className="button button--ghost" onClick={() => { setReplayIndex(0); setIsPlaying(false); }} disabled={!replayEvents.length}>Reset</button>
            </div>
            <div className="replayScrubber">
              <input type="range" min={0} max={Math.max(0, replayEvents.length - 1)} value={Math.min(replayIndex, Math.max(0, replayEvents.length - 1))} onChange={(e) => { setReplayIndex(Number(e.target.value)); setIsPlaying(false); }} disabled={!replayEvents.length} />
              <div className="traceSummaryBar">
                <span>Replay step {replayEvents.length ? replayIndex + 1 : 0} / {replayEvents.length}</span>
                <span>{visibleReplayEvents.at(-1)?.tool || 'Select a trace'}</span>
                <span>{visibleReplayEvents.at(-1)?.matched_rule_label ? `Rule: ${visibleReplayEvents.at(-1)?.matched_rule_label}` : 'No rule highlighted yet'}</span>
              </div>
            </div>
          </div>
          <div className="hero__right">
            <TraceGraph trace={replayTrace as any} onOpenDecision={onOpenDecision} compact={false} onOpenRule={() => {}} />
          </div>
        </section>

        <section className="layout layout--equalCols layout--bottomSupport">
          <div className="card">
            <div className="sectionHeader"><div><div className="eyebrow">Trace catalogue</div><h3>Recent traces</h3></div></div>
            <div className="traceList scrollPanel scrollPanel--medium">{traceCatalogue.length ? (traceCatalogue.map((trace: TraceSummary) => (<button key={trace.trace_id} className="traceCard" onClick={() => setSelectedTraceId(trace.trace_id)}><div><div className="traceCard__title">{trace.trace_id}</div><div className="traceCard__meta">{trace.summary?.event_count || 0} events · {Object.keys(trace.summary?.statuses || {}).join(', ') || 'no statuses'}</div></div><div className={`traceCard__status badge badge--${statusTone(Object.entries(trace.summary?.statuses || {}).sort((a: any, b: any) => b[1] - a[1])[0]?.[0] || 'allowed')}`}>{Object.entries(trace.summary?.statuses || {}).sort((a: any, b: any) => b[1] - a[1])[0]?.[0] || 'allowed'}</div></button>))) : <div className="emptyState"><strong>No traces available yet.</strong><span className="muted">Use the Run OSS demo button to seed a complete allow / warn / block trace set.</span></div>}</div>
          </div>

          <div className="card">
            <div className="sectionHeader"><div><div className="eyebrow">Scenario simulation</div><h3>What changes if policy changes?</h3></div><button className="button" onClick={runSimulation} disabled={!selectedTrace?.trace_id || simulating}>{simulating ? 'Simulating…' : 'Run simulation'}</button></div>
            <p className="muted">Paste a candidate policy fragment, replay it across the selected trace, and compare original versus simulated outcomes before changing production policy.</p>
            <textarea className="editor editor--compact" value={simulationDraft} onChange={(e) => setSimulationDraft(e.target.value)} spellCheck={false} />
            {simulationResult ? <div className="simulationPanel"><div className="traceSummaryBar"><span>Allow {simulationResult.summary?.allow || 0}</span><span>Warn {simulationResult.summary?.warn || 0}</span><span>Block {simulationResult.summary?.block || 0}</span></div><div className="eventRail scrollPanel scrollPanel--medium">{(simulationResult.results || []).slice(0, 6).map((row: any) => (<button key={row.event_id} className="eventRow" onClick={() => onOpenDecision(row.event_id)}><div className={classNames('eventRow__dot', `is-${statusTone(row.simulated_status === 'warn' ? 'warned' : row.simulated_status === 'block' ? 'blocked' : 'allowed')}`)} /><div className="eventRow__main"><div className="eventRow__title">Event {row.event_id} {row.changed ? <span className="badge badge--warn">changed</span> : <span className="badge badge--ok">same</span>}</div><div className="eventRow__meta">Original: {row.original_status} · Simulated: {row.simulated_status}</div></div><div className="eventRow__score">{row.explanations?.length || 0}</div></button>))}</div></div> : null}
          </div>
        </section>
      </section>
    </div>
  );
}



function RulesPage({ policy, policyText, setPolicyText, templates, onApplyTemplate, onSave, loading, ruleFocus, ruleFocusBucket, ruleFocusToken }: any) {
  const [selectedBucket, setSelectedBucket] = useState<typeof RULE_BUCKETS[number]>('block');
  const [selectedRuleIndex, setSelectedRuleIndex] = useState(0);
  const [highlightedRuleKey, setHighlightedRuleKey] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [templateMode, setTemplateMode] = useState<'replace' | 'merge'>('merge');
  const ruleRailRef = useRef<HTMLDivElement | null>(null);
  const ruleEditorPaneRef = useRef<HTMLDivElement | null>(null);
  const ruleItemRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const highlightTimerRef = useRef<number | null>(null);

  const workingPolicy = useMemo(() => safeParsePolicy(policyText, policy), [policyText, policy]);
  const activeRules = workingPolicy[selectedBucket] || [];
  const activeRule = activeRules[selectedRuleIndex] || null;

  useEffect(() => {
    if (selectedRuleIndex > Math.max(0, activeRules.length - 1)) {
      setSelectedRuleIndex(Math.max(0, activeRules.length - 1));
    }
  }, [selectedRuleIndex, activeRules.length, selectedBucket]);

  function ruleKey(bucket: string, idx: number) {
    return `${bucket}:${idx}`;
  }

  function scrollSelectedRuleIntoView(bucket = selectedBucket, index = selectedRuleIndex) {
    const target = ruleItemRefs.current[ruleKey(bucket, index)];
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'nearest' });
    }
  }

  function resetRuleEditorScroll() {
    if (ruleEditorPaneRef.current) ruleEditorPaneRef.current.scrollTop = 0;
  }

  function flashRuleHighlight(bucket: string, index: number) {
    const nextKey = ruleKey(bucket, index);
    if (highlightTimerRef.current) window.clearTimeout(highlightTimerRef.current);
    setHighlightedRuleKey(nextKey);
    highlightTimerRef.current = window.setTimeout(() => {
      setHighlightedRuleKey((current) => (current === nextKey ? '' : current));
      highlightTimerRef.current = null;
    }, 2600);
  }

  useEffect(() => {
    requestAnimationFrame(() => {
      scrollSelectedRuleIntoView();
      resetRuleEditorScroll();
    });
  }, [selectedBucket, selectedRuleIndex]);

  useEffect(() => () => {
    if (highlightTimerRef.current) window.clearTimeout(highlightTimerRef.current);
  }, []);

  useEffect(() => {
    if (!ruleFocus && !ruleFocusToken) return;
    const wanted = String(ruleFocus || '').trim().toLowerCase();
    const wantedToken = String(ruleFocusToken || '').trim();
    if (!wanted && !wantedToken) return;

    const orderedBuckets = [
      ...(ruleFocusBucket && RULE_BUCKETS.includes(ruleFocusBucket as any) ? [ruleFocusBucket as typeof RULE_BUCKETS[number]] : []),
      ...RULE_BUCKETS.filter((bucket) => bucket !== ruleFocusBucket),
    ];

    const findRuleIndex = (bucket: typeof RULE_BUCKETS[number]) => (workingPolicy[bucket] || []).findIndex((rule: any) => {
      if (wantedToken && ruleFingerprint(rule) === wantedToken) return true;
      if (!wanted) return false;
      const summary = summarizeRule(rule).toLowerCase();
      const fields = [
        rule?.title,
        rule?.name,
        rule?.description,
        rule?.reason,
        summary,
      ].filter(Boolean).map((value: any) => String(value).toLowerCase());
      return fields.some((value: string) => value === wanted || value.includes(wanted) || wanted.includes(value));
    });

    for (const bucket of orderedBuckets) {
      const idx = findRuleIndex(bucket);
      if (idx >= 0) {
        setSelectedBucket(bucket);
        setSelectedRuleIndex(idx);
        requestAnimationFrame(() => {
          scrollSelectedRuleIntoView(bucket, idx);
          resetRuleEditorScroll();
          flashRuleHighlight(bucket, idx);
        });
        return;
      }
    }
  }, [ruleFocus, ruleFocusBucket, ruleFocusToken, policyText]);

  function updateDoc(nextDoc: PolicyDoc) {
    setPolicyText(JSON.stringify(dedupePolicyDoc(ensurePolicyDoc(nextDoc)), null, 2));
  }

  function selectRule(bucket: typeof RULE_BUCKETS[number], index: number) {
    setSelectedBucket(bucket);
    setSelectedRuleIndex(index);
    requestAnimationFrame(() => {
      scrollSelectedRuleIntoView(bucket, index);
      resetRuleEditorScroll();
    });
  }

  function applyTemplateToBuilder(template: any) {
    const templateDoc = dedupePolicyDoc(ensurePolicyDoc(template?.template || template || {}));
    const nextDoc = templateMode === 'replace'
      ? templateDoc
      : mergePolicyWithoutDuplicates(workingPolicy, templateDoc);

    setPolicyText(JSON.stringify(nextDoc, null, 2));

    const focusDoc = templateMode === 'replace' ? nextDoc : templateDoc;
    const nextBucket = pickFirstNonEmptyBucket(focusDoc);
    const targetRule = focusDoc[nextBucket]?.[0] || nextDoc[nextBucket]?.[0] || null;
    const nextIndex = targetRule
      ? Math.max(0, nextDoc[nextBucket].findIndex((rule: any) => ruleFingerprint(rule) === ruleFingerprint(targetRule)))
      : 0;

    selectRule(nextBucket, nextIndex);
  }

  function mutateRule(mutator: (rule: any) => any) {
    const nextDoc = ensurePolicyDoc(workingPolicy);
    const bucketRules = [...nextDoc[selectedBucket]];
    const current = bucketRules[selectedRuleIndex] || {};
    bucketRules[selectedRuleIndex] = mutator({ ...current });
    nextDoc[selectedBucket] = bucketRules;
    updateDoc(nextDoc);
  }

  function addRule(bucket = selectedBucket) {
    const nextDoc = ensurePolicyDoc(workingPolicy);
    const bucketRules = [...nextDoc[bucket]];
    bucketRules.push({ title: 'New rule', enabled: true, type: bucket === 'allow' ? '' : 'http_request' });
    nextDoc[bucket] = bucketRules;
    updateDoc(nextDoc);
    selectRule(bucket, bucketRules.length - 1);
  }

  function duplicateRule() {
    if (!activeRule) return;
    const nextDoc = ensurePolicyDoc(workingPolicy);
    const bucketRules = [...nextDoc[selectedBucket]];
    bucketRules.splice(selectedRuleIndex + 1, 0, { ...activeRule, title: `${summarizeRule(activeRule)} copy` });
    nextDoc[selectedBucket] = bucketRules;
    updateDoc(nextDoc);
    selectRule(selectedBucket, selectedRuleIndex + 1);
  }

  function deleteRule() {
    if (!activeRule) return;
    const nextDoc = ensurePolicyDoc(workingPolicy);
    const bucketRules = [...nextDoc[selectedBucket]];
    bucketRules.splice(selectedRuleIndex, 1);
    nextDoc[selectedBucket] = bucketRules;
    updateDoc(nextDoc);
    selectRule(selectedBucket, Math.max(0, selectedRuleIndex - 1));
  }

  function moveRule(direction: -1 | 1) {
    const target = selectedRuleIndex + direction;
    if (target < 0 || target >= activeRules.length) return;
    const nextDoc = ensurePolicyDoc(workingPolicy);
    const bucketRules = [...nextDoc[selectedBucket]];
    const [rule] = bucketRules.splice(selectedRuleIndex, 1);
    bucketRules.splice(target, 0, rule);
    nextDoc[selectedBucket] = bucketRules;
    updateDoc(nextDoc);
    selectRule(selectedBucket, target);
  }

  function updateCustomEntry(index: number, patch: Partial<{ key: string; operator: string; value: any; mode: string }>) {
    mutateRule((rule) => {
      const entries = customRuleEntries(rule).map(([key, expected]) => ({
        key,
        operator: getRuleOperator({ [key]: expected }, key, 'eq'),
        value: getRuleValue({ [key]: expected }, key),
        mode: Array.isArray(getRuleValue({ [key]: expected }, key)) ? 'list' : typeof getRuleValue({ [key]: expected }, key) === 'number' ? 'number' : typeof getRuleValue({ [key]: expected }, key) === 'boolean' ? 'boolean' : 'text',
      }));
      entries[index] = { ...entries[index], ...patch };
      for (const [key] of Object.entries(rule)) {
        if (!['enabled', 'priority', 'description', 'reason', 'title', 'name', 'type', 'tool'].includes(key) && !String(key).startsWith('classifier:') && !['field:url', 'field:domain', 'field:args.args', 'field:risk_score', 'field:metadata.behavior.suspicious_sequence', 'field:metadata.behavior.previous_blocked'].includes(key)) {
          delete rule[key];
        }
      }
      for (const entry of entries) {
        if (!entry.key) continue;
        const value = coerceRuleInput(String(entry.value ?? ''), entry.mode as any);
        Object.assign(rule, setRuleOperatorValue(rule, entry.key, entry.operator || 'eq', value));
      }
      return rule;
    });
  }

  function addCustomEntry() {
    mutateRule((rule) => {
      rule['field:route_target'] = { contains: '' };
      return rule;
    });
  }

  const templateCards = Array.isArray(templates) ? templates : [];
  const parseError = (() => { try { JSON.parse(policyText); return ''; } catch (error: any) { return error?.message || 'Invalid JSON'; } })();

  return (
    <div className="pageGrid">
      <section className="layout layout--twoThirds rulesLayout">
        <div className="stack">
          <div className="card">
            <div className="sectionHeader">
              <div>
                <div className="eyebrow">Rule sets</div>
                <h3>Interactive policy builder</h3>
              </div>
              <div className="toggleRow">
                <button type="button" className="button button--ghost" onClick={() => addRule()}>New rule</button>
                <button type="button" className="button" onClick={onSave} disabled={loading || !!parseError}>{loading ? 'Saving…' : 'Validate & save'}</button>
              </div>
            </div>
            <div className="bucketTabs">
              {RULE_BUCKETS.map((bucket) => (
                <button
                  type="button"
                  key={bucket}
                  className={classNames('bucketTab', selectedBucket === bucket && 'is-active')}
                  onClick={() => selectRule(bucket, 0)}
                >
                  <span>{bucket}</span>
                  <strong>{workingPolicy[bucket].length}</strong>
                </button>
              ))}
            </div>
            <div className="rulesSplit">
              <div className="ruleRail" ref={ruleRailRef}>
                <div className="ruleRail__header">
                  <div>
                    <div className="subheading">{selectedBucket} rules</div>
                    <p className="muted">Grouped the way analysts expect: block, warn, monitor, and allow.</p>
                  </div>
                </div>
                <div className="ruleList">
                  {activeRules.map((rule: any, idx: number) => (
                    <button
                      type="button"
                      key={idx}
                      ref={(node) => { ruleItemRefs.current[ruleKey(selectedBucket, idx)] = node; }}
                      className={classNames('ruleCard', idx === selectedRuleIndex && 'is-active', highlightedRuleKey === ruleKey(selectedBucket, idx) && 'is-highlighted')}
                      onClick={() => selectRule(selectedBucket, idx)}
                    >
                      <div>
                        <div className="ruleCard__title">{summarizeRule(rule)}</div>
                        <div className="ruleCard__meta">{rule.type || 'any type'} {rule.tool ? `· ${rule.tool}` : ''}</div>
                      </div>
                      <div className="ruleCard__flags">
                        {rule.enabled === false ? <span className="badge">disabled</span> : null}
                        <span className={`badge badge--${selectedBucket === 'block' ? 'danger' : selectedBucket === 'warn' ? 'warn' : 'ok'}`}>{selectedBucket}</span>
                      </div>
                    </button>
                  ))}
                  {!activeRules.length ? (
                    <div className="emptyState">
                      <strong>No {selectedBucket} rules yet</strong>
                      <p className="muted">Create the first rule in this group and Arbiter will preserve the JSON under the hood.</p>
                      <button type="button" className="button" onClick={() => addRule(selectedBucket)}>Create {selectedBucket} rule</button>
                    </div>
                  ) : null}
                </div>
              </div>

              <div className="ruleEditorPane" ref={ruleEditorPaneRef}>
                {activeRule ? (
                  <div className="ruleEditor">
                    <div className="ruleEditor__toolbar">
                      <div>
                        <div className="eyebrow">Selected rule</div>
                        <h4>{summarizeRule(activeRule)}</h4>
                      </div>
                      <div className="toggleRow">
                        <button type="button" className="button button--ghost" onClick={() => moveRule(-1)} disabled={selectedRuleIndex === 0}>Up</button>
                        <button type="button" className="button button--ghost" onClick={() => moveRule(1)} disabled={selectedRuleIndex === activeRules.length - 1}>Down</button>
                        <button type="button" className="button button--ghost" onClick={duplicateRule}>Duplicate</button>
                        <button type="button" className="button button--ghost" onClick={deleteRule}>Delete</button>
                      </div>
                    </div>

                    <div className="ruleEditorGrid">
                      <label className="formField"><span>Rule name</span><input className="input" value={String(activeRule.title || activeRule.name || '')} onChange={(e) => mutateRule((rule) => setRuleSimpleValue(setRuleSimpleValue(rule, 'title', e.target.value), 'name', ''))} /></label>
                      <label className="formField"><span>Action type</span><input className="input" value={String(activeRule.type || '')} onChange={(e) => mutateRule((rule) => setRuleSimpleValue(rule, 'type', e.target.value))} placeholder="http_request, process_spawn, sql_query" /></label>
                      <label className="formField"><span>Tool name</span><input className="input" value={String(activeRule.tool || '')} onChange={(e) => mutateRule((rule) => setRuleSimpleValue(rule, 'tool', e.target.value))} placeholder="requests.get" /></label>
                      <label className="formField"><span>Priority</span><input className="input" type="number" value={String(activeRule.priority ?? '')} onChange={(e) => mutateRule((rule) => setRuleSimpleValue(rule, 'priority', e.target.value === '' ? '' : Number(e.target.value)))} /></label>
                      <label className="formField formField--wide"><span>Description</span><textarea className="input textarea" value={String(activeRule.description || activeRule.reason || '')} onChange={(e) => mutateRule((rule) => setRuleSimpleValue(setRuleSimpleValue(rule, 'description', e.target.value), 'reason', ''))} /></label>
                    </div>

                    <label className="switchRow"><input type="checkbox" checked={activeRule.enabled !== false} onChange={(e) => mutateRule((rule) => setRuleSimpleValue(rule, 'enabled', e.target.checked ? true : false))} /> Enabled</label>

                    <div className="logicBuilder">
                      <div className="subheading">Rule logic builder</div>
                      <div className="logicFlow">
                        <div className="logicNode"><strong>IF</strong><span>{activeRule.type || 'any action'}{activeRule.tool ? ` · ${activeRule.tool}` : ''}</span></div>
                        <div className="logicConnector">AND</div>
                        <div className="logicNode"><strong>WHEN</strong><span>{customRuleEntries(activeRule).length + ADVANCED_FIELDS.filter((field) => Boolean(getRuleValue(activeRule, field.key))).length + CLASSIFIER_KEYS.filter((key) => Boolean(activeRule[`classifier:${key}`])).length} active conditions</span></div>
                        <div className="logicConnector">THEN</div>
                        <div className={`logicNode logicNode--${selectedBucket === 'block' ? 'danger' : selectedBucket === 'warn' ? 'warn' : 'ok'}`}><strong>{selectedBucket.toUpperCase()}</strong><span>{activeRule.description || activeRule.reason || 'policy outcome'}</span></div>
                      </div>
                    </div>

                    <div className="formSection">
                      <div className="subheading">Common matches</div>
                      <div className="ruleEditorGrid">
                        {ADVANCED_FIELDS.map((field) => field.valueType === 'boolean' ? (
                          <label key={field.key} className="switchRow switchRow--card">
                            <input type="checkbox" checked={Boolean(getRuleValue(activeRule, field.key))} onChange={(e) => mutateRule((rule) => setRuleOperatorValue(rule, field.key, field.operator, e.target.checked))} />
                            <span>{field.label}</span>
                          </label>
                        ) : (
                          <label key={field.key} className="formField"><span>{field.label}</span><input className="input" placeholder={field.placeholder || ''} value={String(getRuleValue(activeRule, field.key) || '')} onChange={(e) => mutateRule((rule) => setRuleOperatorValue(rule, field.key, field.operator, e.target.value))} /></label>
                        ))}
                        <label className="formField"><span>Risk score at least</span><input className="input" type="number" value={getRuleOperator(activeRule, 'field:risk_score') === 'gte' ? String(getRuleValue(activeRule, 'field:risk_score') || '') : ''} onChange={(e) => mutateRule((rule) => setRuleOperatorValue(rule, 'field:risk_score', 'gte', e.target.value === '' ? '' : Number(e.target.value)))} /></label>
                        <label className="formField"><span>Risk score at most</span><input className="input" type="number" value={getRuleOperator(activeRule, 'field:risk_score') === 'lte' ? String(getRuleValue(activeRule, 'field:risk_score') || '') : ''} onChange={(e) => mutateRule((rule) => setRuleOperatorValue(rule, 'field:risk_score', 'lte', e.target.value === '' ? '' : Number(e.target.value)))} /></label>
                      </div>
                    </div>

                    <div className="formSection">
                      <div className="subheading">Classifier hits</div>
                      <div className="classifierGrid">
                        {CLASSIFIER_KEYS.map((classifier) => (
                          <label key={classifier} className="switchRow switchRow--card">
                            <input type="checkbox" checked={Boolean(activeRule[`classifier:${classifier}`])} onChange={(e) => mutateRule((rule) => setRuleSimpleValue(rule, `classifier:${classifier}`, e.target.checked ? true : ''))} />
                            <span>{classifier.replace(/_/g, ' ')}</span>
                          </label>
                        ))}
                      </div>
                    </div>

                    <div className="formSection">
                      <div className="sectionHeader sectionHeader--tight">
                        <div>
                          <div className="subheading">Custom conditions</div>
                          <p className="muted">Keep the flexible engine, but edit conditions with fields instead of raw JSON.</p>
                        </div>
                        <button type="button" className="button button--ghost" onClick={addCustomEntry}>Add condition</button>
                      </div>
                      <div className="customList">
                        {customRuleEntries(activeRule).map(([key, expected], idx) => {
                          const entryRule = { [key]: expected };
                          const operator = getRuleOperator(entryRule, key, 'eq');
                          const rawValue = getRuleValue(entryRule, key);
                          const valueMode = Array.isArray(rawValue) ? 'list' : typeof rawValue === 'number' ? 'number' : typeof rawValue === 'boolean' ? 'boolean' : 'text';
                          return (
                            <div key={`${key}-${idx}`} className="customRow">
                              <input className="input" value={key} onChange={(e) => updateCustomEntry(idx, { key: e.target.value })} placeholder="field:route_target" />
                              <select className="input input--small" value={operator} onChange={(e) => updateCustomEntry(idx, { operator: e.target.value })}>{OPERATOR_OPTIONS.map((op) => <option key={op} value={op}>{op}</option>)}</select>
                              <input className="input" value={Array.isArray(rawValue) ? rawValue.join(', ') : String(rawValue ?? '')} onChange={(e) => updateCustomEntry(idx, { value: e.target.value, mode: valueMode })} placeholder="value" />
                            </div>
                          );
                        })}
                        {!customRuleEntries(activeRule).length ? <div className="muted">No extra conditions on this rule.</div> : null}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="emptyState"><strong>Select a rule</strong><p className="muted">Pick a rule from the grouped list, or create a new one in this bucket.</p></div>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="stack">
          <div className="card">
            <div className="sectionHeader">
              <div>
                <div className="eyebrow">Templates</div>
                <h3>Quick starting points</h3>
              </div>
              <div className="toggleRow">
                <button type="button" className={classNames('segmented', templateMode === 'merge' && 'is-active')} onClick={() => setTemplateMode('merge')}>Merge</button>
                <button type="button" className={classNames('segmented', templateMode === 'replace' && 'is-active')} onClick={() => setTemplateMode('replace')}>Replace</button>
              </div>
            </div>
            <div className="templateList">
              {templateCards.map((template: any, idx: number) => {
                const doc = ensurePolicyDoc(template.template || template || {});
                return (
                  <button type="button" key={idx} className="templateCard templateCard--stacked" onClick={() => applyTemplateToBuilder(template)}>
                    <strong>{template.name || `Template ${idx + 1}`}</strong>
                    <div className="templateCounts">{RULE_BUCKETS.map((bucket) => <span key={bucket}>{bucket}: {doc[bucket].length}</span>)}</div>
                    <code>{JSON.stringify(doc).slice(0, 180)}…</code>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="card">
            <div className="sectionHeader">
              <div>
                <div className="eyebrow">Advanced</div>
                <h3>Raw policy document</h3>
              </div>
              <button type="button" className="button button--ghost" onClick={() => setShowAdvanced((v) => !v)}>{showAdvanced ? 'Hide JSON' : 'Show JSON'}</button>
            </div>
            <p className="muted">The visual builder writes straight back to the real OSS policy file, so advanced users can still inspect or hand-edit the underlying JSON.</p>
            {parseError ? <div className="banner banner--error">JSON error: {parseError}</div> : null}
            {showAdvanced ? <textarea className="editor editor--compact" value={policyText} onChange={(e) => setPolicyText(e.target.value)} spellCheck={false} /> : null}
          </div>
        </div>
      </section>
    </div>
  );
}

function DecisionPage({ detail, onOpenDecision, onOpenRule }: any) {
  const event = detail.event || {};
  const action = event.action || {};
  return (
    <div className="pageGrid">
      <section className="layout layout--twoThirds">
        <div className="stack">
          <div className="card">
            <div className="sectionHeader">
              <div>
                <div className="eyebrow">Decision details</div>
                <h3>{action.tool || action.type || 'event'} <span className={`badge badge--${statusTone(event.status)}`}>{event.status}</span></h3>
              </div>
              <div className="toggleRow">
                {detail.neighbors?.previous_event_id ? <button className="button button--ghost" onClick={() => onOpenDecision(detail.neighbors.previous_event_id)}>Previous</button> : null}
                {detail.neighbors?.next_event_id ? <button className="button button--ghost" onClick={() => onOpenDecision(detail.neighbors.next_event_id)}>Next</button> : null}
              </div>
            </div>
            <div className="detailGrid">
              <KeyValue label="Timestamp" value={fmtTs(event.timestamp)} />
              <KeyValue label="Agent" value={action.agent_name} />
              <KeyValue label="Trace" value={event.trace_id} />
              <KeyValue label="Risk" value={`${detail.explainability?.risk_score ?? action.risk_score ?? 0}/100`} />
              <KeyValue label="Decision reason" value={detail.explainability?.reason || event.decision?.reason} />
              <KeyValue label="Triggered rule" value={detail.explainability?.rule_label || deriveMatchedRuleLabel(event)} />
              <KeyValue label="Step type" value={detail.explainability?.event_role_label || 'Recorded trace step'} />
              <KeyValue label="Route" value={event.decision?.route_target || action.route_target} />
              <KeyValue label="Scored because" value={detail.explainability?.score_summary || summarizeRiskReasonLabels(detail.explainability?.risk_reasons || []) || 'No scoring explanation recorded'} />
            </div>
            <div className="decisionNarrative">
              <div className={`decisionCallout decisionCallout--${eventRoleTone(detail.explainability)}`}>
                <strong>{detail.explainability?.event_role_label || 'Recorded trace step'}</strong>
                <span>{eventRoleDescription(detail.explainability)}</span>
              </div>
              <div className="subheading">Decision journey</div>
              <div className="journeyList">
                <div className="journeyStep"><span className="journeyStep__index">1</span><div><strong>{action.agent_name || 'Agent'}</strong><span>selected the <code>{action.tool || action.type || 'action'}</code> tool</span></div></div>
                <div className="journeyStep"><span className="journeyStep__index">2</span><div><strong>Sent payload</strong><span>{displayValue(event.input_payload || action.args || action.payload || 'No payload recorded')}</span></div></div>
                <div className="journeyStep"><span className="journeyStep__index">3</span><div><strong>Risk evaluation</strong><span>{detail.explainability?.score_summary || summarizeRiskReasonLabels(detail.explainability?.risk_reasons || []) || 'No scoring explanation recorded'}</span></div></div>
                <div className="journeyStep"><span className="journeyStep__index">4</span><div><strong>Triggered policy</strong><span><strong>{detail.explainability?.rule_label || deriveMatchedRuleLabel(event) || 'No explicit rule hit recorded'}</strong>{detail.explainability?.trigger_summary ? ` · ${detail.explainability?.trigger_summary}` : ''}</span></div></div>
                <div className="journeyStep journeyStep--decision"><span className="journeyStep__index">5</span><div><strong>Final decision</strong><span>{detail.explainability?.effective_action || event.status} · {detail.explainability?.reason || event.decision?.reason || 'No reason recorded'}{detail.explainability?.inherited_decision_context ? ' · context carried forward from earlier trace step' : ''}</span></div></div>
              </div>
              <div className="ruleJumpRow">
                {Array.from(new Set([detail.explainability?.rule_label, deriveMatchedRuleLabel(event), event?.decision?.rule_name, event?.decision?.triggered_rule].filter(Boolean) as string[])).map((label: string) => (
                  <button key={label} className="badge badge--rule badge--clickable" onClick={() => onOpenRule(label, bucketFromStatus(event.status), detail.explainability?.matched_rule || event?.decision?.matched_rule)}>Open rule · {label}</button>
                ))}
              </div>
            </div>
            <div className="codeGrid">
              <CodeCard title="Action" value={action} />
              <CodeCard title="Input payload" value={event.input_payload} />
              <CodeCard title="Output payload" value={event.output_payload} />
              <div className="codeCard">
                <div className="subheading">Why this triggered</div>
                <div className="explainPanel">
                  <div className="explainPanel__headline">
                    <strong>{detail.explainability?.rule_label || deriveMatchedRuleLabel(event) || 'No explicit rule hit recorded'}</strong>
                    <span>{detail.explainability?.effective_action || event.status}</span>
                  </div>
                  <div className="explainPanel__summary">{detail.explainability?.trigger_summary || detail.explainability?.rule_match_summary || summarizeMatchedFields(detail.explainability?.matched_fields || [], 3) || detail.explainability?.reason || 'No specific rule-field explanation was captured for this event.'}</div>
                  <div className="explainPanel__summary"><strong>Risk score:</strong> {detail.explainability?.score_summary || 'No scoring explanation recorded.'}</div>
                  {detail.explainability?.inherited_decision_context ? <div className="explainPanel__note">This step appears to inherit a previous warn/block context rather than introducing new scored risk on its own.</div> : null}
                </div>
                <div className="chipGrid">
                  {(detail.explainability?.matched_fields || []).map((row: any, idx: number) => <div key={idx} className="chip"><strong>{formatRuleFieldLabel(row.field)}</strong><span>{describeMatchedField(row)}</span><code>{compactValue(row.actual)}</code></div>)}
                  {!(detail.explainability?.matched_fields || []).length ? <div className="muted">No rule-field explanation was captured for this event.</div> : null}
                </div>
                {(detail.explainability?.risk_reason_labels || []).length ? <div className="chipGrid">{(detail.explainability?.risk_reason_labels || []).map((label: string, idx: number) => <div key={`${label}-${idx}`} className="chip chip--reason"><strong>Score driver</strong><span>{label}</span></div>)}</div> : null}
              </div>
            </div>
          </div>

          <div className="card">
            <div className="sectionHeader">
              <div>
                <div className="eyebrow">Workflow context</div>
                <h3>Related events</h3>
              </div>
            </div>
            <div className="eventRail">
              {(detail.workflow_events || []).map((row: any) => (
                <button key={row.id} className="eventRow" onClick={() => onOpenDecision(row.id)}>
                  <div className={classNames('eventRow__dot', `is-${statusTone(row.status)}`)} />
                  <div className="eventRow__main">
                    <div className="eventRow__title">{row.action?.tool || row.action?.type || 'event'}</div>
                    <div className="eventRow__meta">{row.action?.agent_name || 'unknown agent'} · {fmtTs(row.timestamp)}</div>
                  </div>
                  <div className="eventRow__score">{Math.round(row.action?.risk_score || 0)}</div>
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="stack">
          <div className="card">
            <div className="sectionHeader">
              <div>
                <div className="eyebrow">Trace graph</div>
                <h3>Flow around this decision</h3>
              </div>
            </div>
            <TraceGraph trace={detail.trace} onOpenDecision={onOpenDecision} onOpenRule={onOpenRule} compact />
          </div>
        </div>
      </section>
    </div>
  );
}

function TraceGraph({ trace, onOpenDecision, onOpenRule, compact }: { trace: TraceSummary | null; onOpenDecision: (id: number) => void; onOpenRule: (label: string, bucket?: string, matchedRule?: any) => void; compact?: boolean; }) {
  if (!trace?.graph?.nodes?.length) return <div className="traceEmpty">No trace selected yet.</div>;
  const nodes = trace.graph.nodes;
  const width = Math.max(920, nodes.length * 220);
  const height = compact ? 320 : 420;
  const laneY = compact ? 110 : 138;
  const eventPositions = nodes.map((node, index) => ({ ...node, x: 80 + (index * 210), y: laneY }));
  const byId = new Map(eventPositions.map((node) => [node.id, node]));
  const eventMap = new Map((trace.events || []).map((event: any) => [event.id, event]));
  const ruleNodes = eventPositions.flatMap((node, index) => {
    const event = eventMap.get(node.id);
    const matchedRule = event?.decision?.matched_rule;
    if (!matchedRule) return [];
    const label = deriveMatchedRuleLabel(event) || deriveRuleLabelFromRuleObject(matchedRule, node.status) || 'Triggered rule';
    const severity = node.status === 'blocked' ? 'danger' : node.status === 'warned' ? 'warn' : 'ok';
    return [{
      id: `rule-${node.id}`,
      parentId: node.id,
      label,
      severity,
      x: node.x,
      y: laneY + (compact ? 118 : 140) + ((index % 2) * 12),
    }];
  });

  if (compact) {
    const steps = (trace.events || []).map((event: any) => normalizeEventRow(event)).sort((a: EventRow, b: EventRow) => (a.timestamp || 0) - (b.timestamp || 0));
    return (
      <div className="traceGraphWrap traceGraphWrap--compact">
        <div className="traceSummaryBar">
          <span>{trace.trace_id}</span>
          <span>{trace.summary.event_count} events</span>
          <span>{fmtTs(trace.summary.start_timestamp)}</span>
        </div>
        <div className="journeyTimeline">
          {steps.map((step: any, index: number) => {
            const event = eventMap.get(step.id) || step;
            const ruleLabels = Array.from(new Set([deriveMatchedRuleLabel(event), deriveRuleLabelFromRuleObject(event?.decision?.matched_rule, step.status), event?.decision?.rule_name, event?.decision?.triggered_rule].filter(Boolean) as string[]));
            return (
              <div key={step.id} className="journeyTimeline__item">
                <button className={`journeyTimeline__card journeyTimeline__card--${statusTone(step.status)}`} onClick={() => onOpenDecision(Number(step.id))}>
                  <div className="journeyTimeline__header"><span className="badge">Step {index + 1}</span><span className={`badge badge--${statusTone(step.status)}`}>{step.status}</span></div>
                  <strong>{step.agent_name || 'agent'} → {step.tool || 'tool'}</strong>
                  <div className="muted">{fmtTs(step.timestamp)} · risk {Math.round(step.risk_score || 0)}</div>
                  <div className="muted">{displayValue(event?.decision?.route_target || step.route_target || step.domain || 'No route recorded')}</div>
                  <div className="muted">{(event?.action?.risk_score || 0) > 0 ? 'Primary scored step' : ((event?.decision?.matched_rule && !(event?.action?.risk_score || 0)) ? 'Follow-on inherited step' : 'Recorded trace step')}</div>
                </button>
                <div className="journeyTimeline__rules">
                  {ruleLabels.length ? ruleLabels.map((label) => <button key={label} className="badge badge--rule badge--clickable" onClick={() => onOpenRule(label, bucketFromStatus(step.status), event?.decision?.matched_rule)}>{label}</button>) : <span className="muted">No explicit rule hit</span>}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  }

  return (
    <div className="traceGraphWrap">
      <div className="traceSummaryBar">
        <span>{trace.trace_id}</span>
        <span>{trace.summary.event_count} events</span>
        <span>{fmtTs(trace.summary.start_timestamp)}</span>
        <span>{ruleNodes.length} triggered rules shown inline</span>
      </div>
      <div className="traceGraphScroller">
        <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="traceSvg">
          <defs>
            <linearGradient id="traceGradient" x1="0%" x2="100%" y1="0%" y2="0%">
              <stop offset="0%" stopColor="rgba(123,97,255,0.18)" />
              <stop offset="100%" stopColor="rgba(76,224,181,0.18)" />
            </linearGradient>
          </defs>
          <rect x="30" y={laneY - 52} width={width - 60} height="104" rx="22" fill="url(#traceGradient)" />
          {ruleNodes.length ? <rect x="30" y={laneY + (compact ? 76 : 92)} width={width - 60} height={compact ? 132 : 162} rx="22" className="traceRuleLane" /> : null}
          {trace.graph.edges.map((edge, idx) => {
            const source = byId.get(edge.source);
            const target = byId.get(edge.target);
            if (!source || !target) return null;
            return <line key={idx} x1={source.x + 72} y1={source.y} x2={target.x - 72} y2={target.y} className={`traceEdge traceEdge--${edge.kind || 'sequence'}`} />;
          })}
          {ruleNodes.map((rule, idx) => {
            const source = byId.get(rule.parentId);
            if (!source) return null;
            return (
              <g key={rule.id}>
                <path d={`M ${source.x} ${source.y + 52} C ${source.x} ${source.y + 76}, ${rule.x} ${rule.y - 58}, ${rule.x} ${rule.y - 34}`} className={`traceEdge traceEdge--triggered traceEdge--${rule.severity}`} />
                <g transform={`translate(${rule.x}, ${rule.y})`} className="traceRuleNode" onClick={() => onOpenRule(String(rule.label), rule.severity === 'danger' ? 'block' : rule.severity === 'warn' ? 'warn' : 'allow', eventMap.get(rule.parentId)?.decision?.matched_rule)}>
                  <rect x="-82" y="-26" width="164" height="52" rx="18" className={`traceRuleNode__card traceRuleNode__card--${rule.severity}`} />
                  <text x="0" y="-3" textAnchor="middle" className="traceRuleNode__title">{String(rule.label).slice(0, 26)}</text>
                  <text x="0" y="15" textAnchor="middle" className="traceRuleNode__meta">triggered rule</text>
                </g>
              </g>
            );
          })}
          {eventPositions.map((node) => {
            const event = eventMap.get(node.id);
            const matchedRule = event?.decision?.matched_rule;
            const matchedLabel = deriveMatchedRuleLabel(event) || deriveRuleLabelFromRuleObject(matchedRule, node.status) || '';
            return (
              <g key={node.id} transform={`translate(${node.x}, ${node.y})`} onClick={() => onOpenDecision(Number(node.id))} className="traceNode">
                <rect x="-72" y="-52" width="144" height="104" rx="24" className={`traceNode__card traceNode__card--${statusTone(node.status)}`} />
                <text x="0" y="-14" textAnchor="middle" className="traceNode__title">{String(node.label || 'event').slice(0, 18)}</text>
                <text x="0" y="10" textAnchor="middle" className="traceNode__meta">{node.status}</text>
                <text x="0" y="34" textAnchor="middle" className="traceNode__risk">risk {Math.round(node.risk_score || 0)}</text>
                {matchedLabel ? <text x="0" y="56" textAnchor="middle" className="traceNode__rule">{String(matchedLabel).slice(0, 16)}</text> : null}
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}

function SankeyPanel({ overview, sourceEvents, onFocus, mode = 'agent_tool_outcome' }: { overview: DashboardPayload; sourceEvents: any[]; onFocus: (opts: { status?: string; search?: string; eventIds?: number[]; label?: string }) => void; mode?: 'agent_tool_outcome' | 'agent_rule_outcome' | 'tool_rule_outcome'; }) {
  const events = (sourceEvents || []).map(normalizeEventRow).filter((event) => event.id);
  const laneMaps: Record<string, Map<string, number>> = { left: new Map(), mid: new Map(), right: new Map() } as any;
  const flowCounts = new Map<string, { value: number; statuses: Record<string, number>; eventIds: number[] }>();
  const pushFlow = (key: string, status: string, eventId: number) => {
    const current = flowCounts.get(key) || { value: 0, statuses: {}, eventIds: [] };
    current.value += 1;
    current.statuses[status] = (current.statuses[status] || 0) + 1;
    current.eventIds.push(eventId);
    flowCounts.set(key, current);
  };
  const leftLabel = mode === 'tool_rule_outcome' ? 'Tools' : 'Agents';
  const midLabel = mode === 'agent_tool_outcome' ? 'Tools' : 'Rules';
  const rightLabel = 'Outcomes';
  for (const event of events) {
    const left = mode === 'tool_rule_outcome' ? (event.tool || 'unknown tool') : (event.agent_name || 'unknown agent');
    const ruleLabel = (event as any).matched_rule_label || deriveMatchedRuleLabel(event) || (event.status === 'allowed' ? 'no rule hit' : `${event.status} decision`);
    const mid = mode === 'agent_tool_outcome' ? (event.tool || 'unknown tool') : ruleLabel;
    const status = event.status || 'allowed';
    const right = ruleLabel && mode !== 'agent_tool_outcome' ? `${status} · ${ruleLabel}` : status;
    laneMaps.left.set(left, (laneMaps.left.get(left) || 0) + 1);
    laneMaps.mid.set(mid, (laneMaps.mid.get(mid) || 0) + 1);
    laneMaps.right.set(right, (laneMaps.right.get(right) || 0) + 1);
    pushFlow(`l|${left}|m|${mid}`, status, event.id);
    pushFlow(`m|${mid}|r|${right}`, status, event.id);
  }
  const leftNodesRaw = Array.from(laneMaps.left.entries()).sort((a,b)=>b[1]-a[1]).slice(0,5);
  const midNodesRaw = Array.from(laneMaps.mid.entries()).sort((a,b)=>b[1]-a[1]).slice(0,6);
  const rightNodesRaw = Array.from(laneMaps.right.entries()).sort((a,b)=>b[1]-a[1]).slice(0,5);
  const maxFlow = Math.max(...Array.from(flowCounts.values()).map((entry) => entry.value), 1);
  const columnX = [80, 400, 720];
  const laneHeight = 56;
  const gap = 18;
  const nodeWidth = 210;
  const buildNodes = (raw: any[], x: number, lane: string, baseY: number) => raw.map(([key, value], i) => ({ key, value, x, y: baseY + i * (laneHeight + gap), lane }));
  const leftNodes = buildNodes(leftNodesRaw, columnX[0], 'left', 34);
  const midNodes = buildNodes(midNodesRaw, columnX[1], 'mid', 20);
  const rightNodes = buildNodes(rightNodesRaw, columnX[2], 'right', 42);
  const nodeByKey = new Map<string, any>();
  [...leftNodes, ...midNodes, ...rightNodes].forEach((node) => nodeByKey.set(`${node.lane}:${node.key}`, node));
  const dominantTone = (statuses: Record<string, number>) => {
    const blocked = statuses.blocked || 0; const warned = statuses.warned || 0;
    return blocked >= warned && blocked > 0 ? 'danger' : warned > 0 ? 'warn' : 'ok';
  };
  const edges: Array<{ source: any; target: any; value: number; tone: string; eventIds: number[] }> = [];
  for (const [key, entry] of flowCounts.entries()) {
    const [fromLane, fromLabel, toLane, toLabel] = key.split('|');
    const from = fromLane === 'l' ? nodeByKey.get(`left:${fromLabel}`) : nodeByKey.get(`mid:${fromLabel}`);
    const to = toLane === 'm' ? nodeByKey.get(`mid:${toLabel}`) : nodeByKey.get(`right:${toLabel}`);
    if (from && to) edges.push({ source: from, target: to, value: entry.value, tone: dominantTone(entry.statuses), eventIds: entry.eventIds });
  }
  const height = Math.max(260, Math.max(leftNodes.length, midNodes.length, rightNodes.length) * (laneHeight + gap) + 40);
  const outcomeTone = (label: string) => label.startsWith('blocked') ? 'danger' : label.startsWith('warned') ? 'warn' : 'ok';
  return (
    <div className="sankeyWrap">
      <div className="traceSummaryBar"><span>{leftLabel} → {midLabel} → {rightLabel}</span><span>{events.length} observed actions</span><span>Click nodes or coloured lanes to jump into filtered activity</span></div>
      <div className="signalLegend"><span><i className="legendSwatch legendSwatch--danger" />Blocked-heavy path</span><span><i className="legendSwatch legendSwatch--warn" />Warn-heavy path</span><span><i className="legendSwatch legendSwatch--ok" />Allow-heavy path</span></div>
      <div className="sankeyScroller">
        <svg width="980" height={height} viewBox={`0 0 980 ${height}`} className="traceSvg">
          <text x="100" y="20" className="traceNode__meta">{leftLabel}</text><text x="420" y="20" className="traceNode__meta">{midLabel}</text><text x="740" y="20" className="traceNode__meta">{rightLabel}</text>
          {edges.map((edge, idx) => {
            const x1 = edge.source.x + nodeWidth; const y1 = edge.source.y + laneHeight / 2; const x2 = edge.target.x; const y2 = edge.target.y + laneHeight / 2; const dx = (x2 - x1) * 0.5;
            return <path key={idx} d={`M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`} className={`sankeyEdge sankeyEdge--${edge.tone}`} style={{ strokeWidth: 8 + (edge.value / maxFlow) * 16 }} onClick={() => onFocus({ eventIds: edge.eventIds, label: `${edge.value} events on ${edge.tone} path` })} />;
          })}
          {[...leftNodes, ...midNodes, ...rightNodes].map((node) => (<g key={`${node.lane}-${node.key}`} className="sankeyNode" transform={`translate(${node.x}, ${node.y})`} onClick={() => {
            if (node.lane === 'left') onFocus({ search: node.key, eventIds: events.filter((event) => (mode === 'tool_rule_outcome' ? event.tool : event.agent_name) === node.key).map((event) => event.id), label: `${leftLabel} focus · ${node.key}` });
            if (node.lane === 'mid') onFocus({ search: node.key, eventIds: events.filter((event) => (mode === 'agent_tool_outcome' ? event.tool : (((event as any).matched_rule_label || deriveMatchedRuleLabel(event) || (event.status === 'allowed' ? 'no rule hit' : `${event.status} decision`)))) === node.key).map((event) => event.id), label: `${midLabel} focus · ${node.key}` });
            if (node.lane === 'right') { const status = node.key.startsWith('blocked') ? 'blocked' : node.key.startsWith('warned') ? 'warned' : 'allowed'; onFocus({ status, eventIds: events.filter((event) => event.status === status).map((event) => event.id), label: `Outcome focus · ${node.key}` }); }
          }}><rect width={nodeWidth} height={laneHeight} rx="18" className={`sankeyNode__card sankeyNode__card--${node.lane === 'right' ? outcomeTone(node.key) : 'neutral'}`} /><text x="16" y="24" className="sankeyNode__title">{String(node.key).slice(0, 28)}</text><text x="16" y="42" className="sankeyNode__meta">{node.value} events</text></g>))}
        </svg>
      </div>
    </div>
  );
}


function MiniTimeline({ data, selectedTimestamp, sourceEvents, onSelectBucket }: { data: any[]; selectedTimestamp?: number | null; sourceEvents?: any[]; onSelectBucket?: (timestamp: number | null, eventIds?: number[]) => void; }) {
  const events = (sourceEvents || []).map(normalizeEventRow);
  const maxSeverity = Math.max(...(data || []).map((d) => ((d.blocked || 0) * 1) + ((d.warned || 0) * 0.65) + ((d.allowed || 0) * 0.3)), 1);
  const maxLatency = Math.max(...(data || []).map((d) => Number(d.avg_latency_ms || 0)), 1);
  return (
    <div className="timelineChart timelineChart--interactive">
      {(data || []).map((point, idx) => {
        const blocked = Number(point.blocked || 0);
        const warned = Number(point.warned || 0);
        const allowed = Number(point.allowed || 0);
        const severity = (blocked * 1) + (warned * 0.65) + (allowed * 0.3);
        const height = Math.max(16, (severity / maxSeverity) * 100);
        const total = blocked + warned + allowed || 1;
        const bucketStart = Math.floor(Number(point.timestamp || 0) / 60) * 60;
        const eventIds = events.filter((event) => Math.floor(Number(event.timestamp || 0) / 60) * 60 === bucketStart).map((event) => event.id);
        const latency = Number(point.avg_latency_ms || 0);
        const latencyOffset = latency > 0 ? Math.max(8, Math.min(98, (latency / maxLatency) * 100)) : 0;
        return (
          <button
            type="button"
            key={idx}
            className={classNames('timelineChart__barWrap', selectedTimestamp === point.timestamp && 'is-active')}
            title={`${fmtTs(point.timestamp)} · blocked ${blocked} · warned ${warned} · allowed ${allowed} · linked ${eventIds.length}${latency ? ` · avg latency ${fmtNum(latency, 1)} ms` : ''}`}
            onClick={() => onSelectBucket?.(point.timestamp, eventIds)}
          >
            <div className="timelineChart__plot">
              {latency > 0 ? <div className="timelineChart__latencyMarker" style={{ bottom: `${latencyOffset}%` }}><span className="timelineChart__latencyDot" /></div> : null}
              <div className="timelineChart__bar timelineChart__bar--stacked" style={{ height: `${height}%` }}>
                <span className="timelineChart__segment timelineChart__segment--danger" style={{ height: `${Math.max(12, (blocked / total) * 100)}%` }} />
                <span className="timelineChart__segment timelineChart__segment--warn" style={{ height: `${Math.max(10, (warned / total) * 100)}%` }} />
                <span className="timelineChart__segment timelineChart__segment--ok" style={{ height: `${Math.max(8, (allowed / total) * 100)}%` }} />
              </div>
            </div>
            <span className="timelineChart__count">{eventIds.length}</span>
            <span className="timelineChart__label">{new Date(point.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
            <span className="timelineChart__latencyValue">{latency ? `${fmtNum(latency, 0)} ms` : '—'}</span>
          </button>
        );
      })}
    </div>
  );
}

function MiniBarList({ title, items }: { title: string; items: Array<{ label: string; value: number }> }) {
  const max = Math.max(...items.map((item) => item.value), 1);
  return (
    <div>
      <div className="subheading">{title}</div>
      <div className="barList">
        {items.map((item) => (
          <div key={item.label} className="barList__row">
            <span>{item.label}</span>
            <div className="barList__track"><div className="barList__fill" style={{ width: `${(item.value / max) * 100}%` }} /></div>
            <strong>{item.value}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}

function MetricCard({ title, value, subtitle, tone, onClick }: any) {
  const Tag: any = onClick ? 'button' : 'div';
  return (
    <Tag className={classNames('metricCard', tone && `metricCard--${tone}`, onClick && 'metricCard--interactive')} onClick={onClick}>
      <div className="metricCard__title">{title}</div>
      <div className="metricCard__value">{value}</div>
      <div className="metricCard__subtitle">{subtitle}</div>
    </Tag>
  );
}

function Stat({ label, value }: any) {
  return <div className="stat"><span>{label}</span><strong>{value}</strong></div>;
}

function KeyValue({ label, value }: { label: string; value: any }) {
  return <div className="kv"><span>{label}</span><strong>{displayValue(value)}</strong></div>;
}

function CodeCard({ title, value }: { title: string; value: any }) {
  return (
    <div className="codeCard">
      <div className="subheading">{title}</div>
      <pre>{displayValue(value)}</pre>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(<Shell />);
