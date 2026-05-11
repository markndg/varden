import React, { useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles/app.css';
import { CoverageGapsPage } from './components/dashboard/CoverageGapsPage';
import { ImpactPage as ImpactPageView } from './components/dashboard/ImpactPage';
import { DecisionPage as DecisionPageView } from './components/dashboard/DecisionPage';
import { OverviewPage as OverviewPageView } from './components/dashboard/OverviewPage';
import { RulesPage as RulesPageView } from './components/dashboard/RulesPage';
import { ADVANCED_FIELDS, CLASSIFIER_KEYS, DashboardPayload, EventDetail, EventRow, OPERATOR_OPTIONS, PolicyDoc, RULE_BUCKETS, TraceOption, TraceSummary } from './lib/types';
import { detailIdFromLocation, pageFromLocation, ruleBucketFromSearch, ruleFocusTokenFromSearch, ruleReturnToFromSearch } from './lib/routing';
import { averageLatencyFromPoints, classNames, fmtNum, fmtTs, fromDateTimeLocalValue, latencyValueFromPoint, toDateTimeLocalValue } from './lib/format';
import { coerceRuleInput, customRuleEntries, dedupePolicyDoc, ensurePolicyDoc, getRuleOperator, getRuleValue, mergePolicyWithoutDuplicates, pickFirstNonEmptyBucket, ruleFingerprint, safeParsePolicy, semanticRuleFingerprint, setRuleOperatorValue, setRuleSimpleValue, summarizeRule, summarizeRuleConditions } from './lib/policy';


async function api<T>(path: string, opts: RequestInit = {}, token?: string): Promise<T> {
  const headers = new Headers(opts.headers || {});
  if (token) {
    if (token.includes('.')) headers.set('Authorization', `Bearer ${token}`);
    else headers.set('x-api-key', token);
  }
  if (opts.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const res = await fetch(path, { ...opts, headers });
  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
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

function normalizeAgentKey(name?: string | null) {
  return String(name || '').trim();
}

function eventMatchesGlobalAgent(event: any, agentFilter: string, normalizeEventRow: (event: any) => EventRow) {
  if (!agentFilter) return true;
  const row = normalizeEventRow(event);
  return normalizeAgentKey(row.agent_name) === agentFilter;
}

function collectAgentNames(overview: DashboardPayload | null): string[] {
  if (!overview) return [];
  const set = new Set<string>();
  for (const row of overview.top_agents || []) {
    const a = normalizeAgentKey((row as any)?.agent);
    if (a) set.add(a);
  }
  for (const row of overview.recent_events || []) {
    const a = normalizeAgentKey((row as any)?.agent_name);
    if (a) set.add(a);
  }
  for (const trace of [...(overview.recent_traces || []), ...(overview.trace_catalogue || [])]) {
    for (const ev of trace?.events || []) {
      const a = normalizeAgentKey((ev as any)?.agent_name || (ev as any)?.action?.agent_name);
      if (a) set.add(a);
    }
    for (const key of Object.keys(trace?.summary?.agents || {})) {
      const a = normalizeAgentKey(key);
      if (a) set.add(a);
    }
  }
  return Array.from(set).sort((a, b) => a.localeCompare(b));
}

function pruneTraceForAgent(trace: any, agentFilter: string, normalizeEventRow: (event: any) => EventRow): any | null {
  if (!trace || !agentFilter) return trace;
  const rawEvents = trace.events || [];
  const filtered = rawEvents.filter((ev: any) => eventMatchesGlobalAgent(ev, agentFilter, normalizeEventRow));
  if (!filtered.length) return null;
  const ids = new Set(filtered.map((ev: any) => Number(ev?.id ?? ev?.action?.id ?? normalizeEventRow(ev).id)).filter((n: number) => n > 0));
  const nodes = (trace.graph?.nodes || []).filter((n: any) => ids.has(Number(n.id)));
  const edges = (trace.graph?.edges || []).filter((e: any) => ids.has(Number(e.source)) && ids.has(Number(e.target)));
  const norm = filtered.map(normalizeEventRow);
  const statuses: Record<string, number> = {};
  const tools: Record<string, number> = {};
  const agents: Record<string, number> = {};
  let start = Infinity;
  let end = -Infinity;
  for (const row of norm) {
    const st = String(row.outcome || eventOutcomeStatus(row) || 'allowed');
    statuses[st] = (statuses[st] || 0) + 1;
    const t = row.tool || 'unknown';
    tools[t] = (tools[t] || 0) + 1;
    const ag = row.agent_name || 'unknown';
    agents[ag] = (agents[ag] || 0) + 1;
    const ts = Number(row.timestamp || 0);
    if (ts) {
      start = Math.min(start, ts);
      end = Math.max(end, ts);
    }
  }
  return {
    ...trace,
    events: filtered,
    graph: { nodes, edges },
    summary: {
      ...(trace.summary || {}),
      event_count: filtered.length,
      statuses,
      tools,
      agents,
      start_timestamp: start === Infinity ? trace.summary?.start_timestamp : start,
      end_timestamp: end === -Infinity ? trace.summary?.end_timestamp : end,
    },
  };
}

function applyAgentScopeToOverview(
  overview: DashboardPayload | null,
  agentFilter: string,
  normalizeEventRow: (event: any) => EventRow,
): DashboardPayload | null {
  if (!overview || !agentFilter) return overview;
  const recent_events = (overview.recent_events || []).filter((row) => eventMatchesGlobalAgent(row, agentFilter, normalizeEventRow));
  const mapTraces = (traces: any[] | undefined) =>
    (traces || []).map((t) => pruneTraceForAgent(t, agentFilter, normalizeEventRow)).filter(Boolean) as any[];
  const recent_traces = mapTraces(overview.recent_traces);
  const trace_catalogue = mapTraces(overview.trace_catalogue);
  const merged = new Map<number, EventRow>();
  for (const row of recent_events.map(normalizeEventRow)) if (row.id) merged.set(row.id, row);
  for (const trace of [...recent_traces, ...trace_catalogue]) {
    for (const ev of trace?.events || []) {
      const row = normalizeEventRow(ev);
      if (row.id) merged.set(row.id, row);
    }
  }
  const allScoped = Array.from(merged.values());
  const top_tools = (() => {
    const m = new Map<string, number>();
    for (const row of allScoped) {
      const t = row.tool || 'unknown';
      m.set(t, (m.get(t) || 0) + 1);
    }
    return Array.from(m.entries()).map(([tool, count]) => ({ tool, count })).sort((a, b) => b.count - a.count).slice(0, 12);
  })();
  const top_agents = (() => {
    const m = new Map<string, number>();
    for (const row of allScoped) {
      const a = row.agent_name || 'unknown';
      m.set(a, (m.get(a) || 0) + 1);
    }
    return Array.from(m.entries()).map(([agent, count]) => ({ agent, count })).sort((a, b) => b.count - a.count);
  })();
  const latencies = allScoped.map((row) => Number((row as any).decision_latency_ms || 0)).filter((n) => n > 0).sort((a, b) => a - b);
  const p95_decision_latency_ms = latencies.length ? latencies[Math.max(0, Math.floor(0.95 * (latencies.length - 1)))] : overview.metrics?.p95_decision_latency_ms;
  const avg_decision_latency_ms = latencies.length
    ? latencies.reduce((s, n) => s + n, 0) / latencies.length
    : overview.metrics?.avg_decision_latency_ms;
  return {
    ...overview,
    recent_events,
    recent_traces,
    trace_catalogue,
    top_tools,
    top_agents,
    metrics: {
      ...(overview.metrics || {}),
      total_events: allScoped.length,
      p95_decision_latency_ms,
      avg_decision_latency_ms,
    },
  };
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
    || deriveRuleLabelFromRuleObject(matchedRule, eventOutcomeStatus(event))
    || decision?.rule_name
    || decision?.triggered_rule
    || null;
  if (explicitLabel) return explicitLabel;
  const status = eventOutcomeStatus(event);
  if (status === 'blocked' || status === 'warned') {
    return decision?.reason || `${status} policy`;
  }
  return null;
}

function normalizedDecisionAction(value?: string | null) {
  const action = String(value || '').trim().toLowerCase();
  if (action === 'block' || action === 'blocked') return 'blocked';
  if (action === 'warn' || action === 'warned') return 'warned';
  if (action === 'monitor') return 'monitor';
  if (action === 'allow' || action === 'allowed') return 'allowed';
  return '';
}

function eventOutcomeStatus(event: any): string {
  const explicitOutcome = normalizedDecisionAction(event?.outcome);
  if (explicitOutcome) return explicitOutcome;
  const effectiveAction = normalizedDecisionAction(event?.effective_action || event?.decision?.effective_action);
  const decisionAction = normalizedDecisionAction(event?.decision_action || event?.decision?.action);
  const storedStatus = normalizedDecisionAction(event?.status || event?.action?.status);
  if (effectiveAction === 'monitor' || decisionAction === 'monitor') return 'monitor';
  return storedStatus || effectiveAction || decisionAction || 'allowed';
}

function eventRuleBucket(event: any): string {
  const outcome = eventOutcomeStatus(event);
  if (outcome === 'blocked') return 'block';
  if (outcome === 'warned') return 'warn';
  if (outcome === 'monitor') return 'monitor';
  return 'allow';
}

function normalizeEventRow(event: any): EventRow & { matched_rule_label?: string | null; parent_event_id?: number | null } {
  const action = event?.action || event || {};
  const decision = event?.decision || {};
  const matchedRuleLabel = deriveMatchedRuleLabel(event);
  const storedStatus = normalizedDecisionAction(event?.status || action?.status) || 'allowed';
  const decisionAction = normalizedDecisionAction(event?.decision_action || decision?.action) || undefined;
  const effectiveAction = normalizedDecisionAction(event?.effective_action || decision?.effective_action || decision?.action) || undefined;
  return {
    id: Number(event?.id || action?.id || 0),
    timestamp: Number(event?.timestamp || action?.timestamp || 0),
    tool: action?.tool,
    agent_name: action?.agent_name,
    status: storedStatus,
    outcome: eventOutcomeStatus({ ...event, status: storedStatus, decision_action: decisionAction, effective_action: effectiveAction }),
    decision_action: decisionAction,
    effective_action: effectiveAction,
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
  if (status === 'monitor') return 'monitor';
  return 'ok';
}

function bucketTone(bucket?: string) {
  if (bucket === 'block') return 'danger';
  if (bucket === 'warn') return 'warn';
  if (bucket === 'monitor') return 'monitor';
  return 'ok';
}

function Shell() {
  const [token, setToken] = usePersistentState<string>('varden.token', '');
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
  const [ruleReturnTo, setRuleReturnTo] = useState<string>(ruleReturnToFromSearch(location.search));
  const [ruleDraft, setRuleDraft] = useState<string>(new URLSearchParams(location.search).get('draft') || '');
  const [routeFocus, setRouteFocus] = useState<string>(new URLSearchParams(location.search).get('focus') || '');
  const [filters, setFilters] = usePersistentState('varden.filters', { search: '', status: 'all', from: '', to: '' });
  const [globalAgentFilter, setGlobalAgentFilter] = usePersistentState<string>('varden.globalAgent', '');
  const [agentScopeMenuOpen, setAgentScopeMenuOpen] = useState(false);
  const agentScopeMenuRef = useRef<HTMLDivElement>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!agentScopeMenuOpen) return;
    const onDocMouseDown = (e: MouseEvent) => {
      if (agentScopeMenuRef.current && !agentScopeMenuRef.current.contains(e.target as Node)) setAgentScopeMenuOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setAgentScopeMenuOpen(false);
    };
    document.addEventListener('mousedown', onDocMouseDown);
    window.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDocMouseDown);
      window.removeEventListener('keydown', onKey);
    };
  }, [agentScopeMenuOpen]);

  useEffect(() => {
    const handlePop = () => {
      setPage(pageFromLocation(location.pathname));
      setDetailId(detailIdFromLocation(location.pathname));
      setRuleFocus(new URLSearchParams(location.search).get('rule') || '');
      setRuleFocusBucket(ruleBucketFromSearch(location.search));
      setRuleFocusToken(ruleFocusTokenFromSearch(location.search));
      setRuleReturnTo(ruleReturnToFromSearch(location.search));
      setRuleDraft(new URLSearchParams(location.search).get('draft') || '');
      setRouteFocus(new URLSearchParams(location.search).get('focus') || '');
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
    if (page === 'rules' || page === 'coverage' || page === 'impact') refreshPolicy().catch((e: any) => setError(e?.message || 'Failed to load policy'));
    if (page === 'decision' && detailId) refreshDetail(detailId).catch((e: any) => setError(e?.message || 'Failed to load event'));
  }, [token, page, detailId, routeFocus]);

  useEffect(() => {
    if (!token || !selectedTraceId) return;
    let cancelled = false;
    api<TraceSummary>(`/traces/${encodeURIComponent(selectedTraceId)}`, {}, token)
      .then((payload) => { if (!cancelled) setSelectedTrace(payload); })
      .catch(() => { if (!cancelled) setSelectedTrace(null); });
    return () => { cancelled = true; };
  }, [token, selectedTraceId]);

  const scopedOverview = useMemo(
    () => applyAgentScopeToOverview(overview, globalAgentFilter, normalizeEventRow),
    [overview, globalAgentFilter],
  );
  const agentCatalog = useMemo(() => collectAgentNames(overview), [overview]);
  const displaySelectedTrace = useMemo(() => {
    if (!selectedTrace) return null;
    if (!globalAgentFilter) return selectedTrace;
    return pruneTraceForAgent(selectedTrace, globalAgentFilter, normalizeEventRow);
  }, [selectedTrace, globalAgentFilter]);

  useEffect(() => {
    if (!globalAgentFilter || !agentCatalog.length) return;
    if (!agentCatalog.includes(globalAgentFilter)) setGlobalAgentFilter('');
  }, [agentCatalog, globalAgentFilter, setGlobalAgentFilter]);

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
    setRuleReturnTo(ruleReturnToFromSearch(search));
    setRuleDraft(new URLSearchParams(path.split('?')[1] || '').get('draft') || '');
    setRouteFocus(new URLSearchParams(path.split('?')[1] || '').get('focus') || '');
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
    const rows = scopedOverview?.recent_events || [];
    return rows.filter((row) => {
      if (filters.status !== 'all' && eventOutcomeStatus(row) !== filters.status) return false;
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
  }, [scopedOverview, filters]);

  const traceCandidates = useMemo(() => {
    const base = scopedOverview ?? overview;
    if (!base) return [];
    const ids = new Set<string>();
    const out: TraceOption[] = [];
    const add = (id: string, label?: string) => {
      if (!id || ids.has(id)) return;
      ids.add(id);
      out.push({ trace_id: id, label: label || id });
    };
    for (const trace of [...(base.trace_catalogue || []), ...(base.recent_traces || [])]) {
      if (trace?.trace_id) add(trace.trace_id);
    }
    for (const event of base.recent_events || []) {
      const traceId = (event as any).trace_id || '';
      if (traceId) add(String(traceId));
    }
    if (!globalAgentFilter) {
      for (const trace of traceOptions) {
        if (trace?.trace_id) add(trace.trace_id, trace.label);
      }
    } else {
      for (const trace of traceOptions) {
        if (trace?.trace_id && ids.has(trace.trace_id)) add(trace.trace_id, trace.label);
      }
    }
    if (selectedTrace?.trace_id) {
      const ok = !globalAgentFilter || pruneTraceForAgent(selectedTrace, globalAgentFilter, normalizeEventRow);
      if (ok) add(selectedTrace.trace_id);
    }
    return out;
  }, [scopedOverview, overview, traceOptions, selectedTrace, globalAgentFilter]);

  useEffect(() => {
    if (!globalAgentFilter) return;
    const valid = new Set(traceCandidates.map((t) => t.trace_id));
    if (selectedTraceId && !valid.has(selectedTraceId)) {
      setSelectedTraceId(traceCandidates[0]?.trace_id || '');
    }
  }, [globalAgentFilter, traceCandidates, selectedTraceId]);

  const currentScanMode = overview?.config?.scan_mode || 'deep';
  const topbarEventCount = globalAgentFilter ? (scopedOverview?.metrics?.total_events ?? 0) : (overview?.metrics?.total_events ?? 0);
  const topbarP95Ms = globalAgentFilter ? (scopedOverview?.metrics?.p95_decision_latency_ms ?? 0) : (overview?.metrics?.p95_decision_latency_ms ?? 0);

  return (
    <div className="shell">
      <div className="shell__bg shell__bg--one" />
      <div className="shell__bg shell__bg--two" />
      <aside className="sidebar">
        <div className="brand">
          <div className="brand__markWrap">
            <img src="/static/assets/varden-icon.png" alt="Varden mark" className="brand__icon" />
            <span className="brand__pulse" aria-hidden="true" />
          </div>
          <div className="brand__copy">
            <div className="brand__eyebrow">Agent Security</div>
            <div className="brand__title">Varden</div>
            <div className="brand__subtitle">Control Plane</div>
          </div>
        </div>
        <nav className="nav">
          <button className={classNames('nav__item', page === 'overview' && 'is-active')} onClick={() => navigate('overview', '/ui')}>Overview</button>
          <button className={classNames('nav__item', page === 'impact' && 'is-active')} onClick={() => navigate('impact', '/ui/impact')}>Rule Impact</button>
          <button className={classNames('nav__item', page === 'rules' && 'is-active')} onClick={() => navigate('rules', '/ui/rules')}>Rules Workspace</button>
          <button className={classNames('nav__item', page === 'coverage' && 'is-active')} onClick={() => navigate('coverage', '/ui/coverage-gaps')}>Coverage Gaps</button>
          {detailId ? <button className={classNames('nav__item', page === 'decision' && 'is-active')} onClick={() => navigate('decision', `/ui/decision/${detailId}`)}>Decision View</button> : null}
        </nav>
        <div className="sidebar__section">
          <div className="sidebar__label">Agent scope</div>
          <div
            className={classNames('sidebarAgentSelect', agentScopeMenuOpen && 'is-open')}
            ref={agentScopeMenuRef}
          >
            <button
              type="button"
              className="sidebarAgentSelect__trigger"
              aria-haspopup="listbox"
              aria-expanded={agentScopeMenuOpen}
              aria-label="Filter entire dashboard by agent"
              onClick={() => setAgentScopeMenuOpen((open) => !open)}
            >
              <span className="sidebarAgentSelect__value">{globalAgentFilter || 'All agents'}</span>
              <span className="sidebarAgentSelect__caret" aria-hidden />
            </button>
            {agentScopeMenuOpen ? (
              <ul className="sidebarAgentSelect__menu" role="listbox" aria-label="Agents">
                <li role="none">
                  <button
                    type="button"
                    role="option"
                    aria-selected={!globalAgentFilter}
                    className={classNames('sidebarAgentSelect__option', !globalAgentFilter && 'is-selected')}
                    onClick={() => { setGlobalAgentFilter(''); setAgentScopeMenuOpen(false); }}
                  >
                    All agents
                  </button>
                </li>
                {agentCatalog.map((name) => (
                  <li key={name} role="none">
                    <button
                      type="button"
                      role="option"
                      aria-selected={globalAgentFilter === name}
                      className={classNames('sidebarAgentSelect__option', globalAgentFilter === name && 'is-selected')}
                      onClick={() => { setGlobalAgentFilter(name); setAgentScopeMenuOpen(false); }}
                    >
                      {name}
                    </button>
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
          <p className="muted sidebarAgentSelect__hint">Charts, traces, rule impact, and coverage use this scope. Rules workspace is unchanged.</p>
        </div>
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
            <h1>{page === 'impact' ? 'Rule impact intelligence' : page === 'rules' ? 'Policy workspace' : page === 'decision' ? 'Decision drilldown' : page === 'coverage' ? 'Policy coverage gaps' : 'Trace and flow mission control'}</h1>
            <p className="muted">{page === 'impact' ? 'See which rules are carrying the heaviest load across live traffic and drill into who they affect, where they fire, and where false positives may be hiding.' : page === 'coverage' ? 'Observed behaviour with little or no active policy coverage. Surface blind spots, inspect why they are uncovered, and draft the next rule faster.' : 'See what the agent attempted, why Varden scored it the way it did, and how policy changed the outcome.'}</p>
          </div>
          <div className="topbar__actions">
            <div className="statusPill">Posture: <strong>{overview?.posture || 'loading'}</strong></div>
            <div className="statusPill">Events: <strong>{topbarEventCount}</strong>{globalAgentFilter ? <span className="statusPill__suffix"> scoped</span> : null}</div>
            <div className="statusPill">P95: <strong>{fmtNum(topbarP95Ms, 1)} ms</strong></div>
          </div>
        </header>

        {error ? <div className="banner banner--error">{error}</div> : null}
        {notice ? <div className="banner banner--ok">{notice}</div> : null}
        {page === 'decision' && detail && globalAgentFilter ? (() => {
          const row = normalizeEventRow(detail.event || detail);
          const an = normalizeAgentKey(row.agent_name);
          if (an && an !== globalAgentFilter) {
            return (
              <div className="banner banner--warn">
                This event is from agent <strong>{an}</strong>, but the sidebar scope is <strong>{globalAgentFilter}</strong>. Clear the agent filter to see the full picture, or switch scope.
              </div>
            );
          }
          return null;
        })() : null}

        {page === 'overview' && overview ? (
          <OverviewPageView
            overview={scopedOverview as DashboardPayload}
            filteredEvents={filteredEvents}
            filters={filters}
            setFilters={setFilters}
            selectedTrace={displaySelectedTrace}
            setSelectedTraceId={setSelectedTraceId}
            token={token}
            traceCandidates={traceCandidates}
            onRunDemo={async () => { if (!token) return; try { const payload = await api<any>('/demo/run', { method: 'POST', body: '{}' }, token); setOverview(payload.dashboard); const traces = await refreshTraceList().catch(() => []); const firstTrace = payload.dashboard?.trace_catalogue?.[0]?.trace_id || payload.dashboard?.recent_traces?.[0]?.trace_id || traces?.[0]?.trace_id || ''; if (firstTrace) setSelectedTraceId(firstTrace); setNotice('OSS demo seeded with allow, warn, and block traces'); } catch (e: any) { setError(e?.message || 'Failed to run demo'); } }}
            onOpenDecision={(id) => navigate('decision', `/ui/decision/${id}`)}
            onOpenRule={(label: string, bucket?: string) => navigate('rules', `/ui/rules?rule=${encodeURIComponent(label)}${bucket ? `&bucket=${encodeURIComponent(bucket)}` : ''}&focus=${Date.now()}`)}
            helpers={{ normalizeEventRow, eventOutcomeStatus, fromDateTimeLocalValue, toDateTimeLocalValue, statusTone, classNames, latencyValueFromPoint, fmtTs, fmtNum, deriveMatchedRuleLabel, averageLatencyFromPoints, ensurePolicyDoc, api, deriveRuleLabelFromRuleObject, eventRuleBucket, displayValue }}
          />
        ) : null}

        {page === 'impact' && overview ? (
          <ImpactPageView
            overview={scopedOverview as DashboardPayload}
            policy={safeParsePolicy(policyText, policy)}
            onOpenDecision={(id: number) => navigate('decision', `/ui/decision/${id}`)}
            onOpenRules={(bucket: string, label: string, token?: string, index?: number) => navigate('rules', `/ui/rules?rule=${encodeURIComponent(label)}&bucket=${encodeURIComponent(bucket)}${token ? `&token=${encodeURIComponent(token)}` : ''}${typeof index === 'number' ? `&index=${index}` : ''}&focus=${Date.now()}`)}
            helpers={{ RULE_BUCKETS, pickFirstNonEmptyBucket, ensurePolicyDoc, dedupePolicyDoc, normalizeEventRow, summarizeRule, summarizeRuleConditions, deriveMatchedRuleLabel, semanticRuleFingerprint, formatRuleFieldLabel, bucketTone, classNames, fmtNum, statusTone, eventOutcomeStatus }}
          />
        ) : null}

        {page === 'rules' ? (
          <RulesPageView
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
            ruleReturnTo={ruleReturnTo}
            ruleDraft={ruleDraft}
            ruleDraftNonce={routeFocus}
            onBackToDecision={(path: string) => navigate('decision', path)}
            helpers={{ RULE_BUCKETS, usePersistentState, safeParsePolicy, classNames, customRuleEntries, dedupePolicyDoc, ensurePolicyDoc, pickFirstNonEmptyBucket, mergePolicyWithoutDuplicates, semanticRuleFingerprint, summarizeRule, summarizeRuleConditions, getRuleOperator, getRuleValue, coerceRuleInput, setRuleOperatorValue, setRuleSimpleValue, ADVANCED_FIELDS, CLASSIFIER_KEYS, OPERATOR_OPTIONS, bucketTone }}
          />
        ) : null}

        {page === 'decision' && detail ? (
          <DecisionPageView
            detail={detail}
            onOpenDecision={(id) => navigate('decision', `/ui/decision/${id}`)}
            onOpenRule={(label: string, bucket?: string, token?: string) => navigate('rules', `/ui/rules?rule=${encodeURIComponent(label)}${bucket ? `&bucket=${encodeURIComponent(bucket)}` : ''}${token ? `&token=${encodeURIComponent(token)}` : ''}&returnTo=${encodeURIComponent(`/ui/decision/${detailId}`)}&focus=${Date.now()}`)}
            helpers={{ statusTone, eventOutcomeStatus, fmtTs, deriveMatchedRuleLabel, summarizeRiskReasonLabels, eventRoleTone, eventRoleDescription, displayValue, eventRuleBucket, semanticRuleFingerprint, formatRuleFieldLabel, describeMatchedField, compactValue, summarizeMatchedFields, deriveRuleLabelFromRuleObject, normalizeEventRow, classNames }}
          />
        ) : null}

        {page === 'coverage' && overview ? (
          <CoverageGapsPage
            overview={scopedOverview as DashboardPayload}
            policy={safeParsePolicy(policyText, policy)}
            onOpenDecision={(id: number) => navigate('decision', `/ui/decision/${id}?focus=${Date.now()}`)}
            onOpenRules={(draftRule: any) => navigate('rules', `/ui/rules?draft=${encodeURIComponent(JSON.stringify(draftRule || {}))}&focus=${Date.now()}`)}
            helpers={{ RULE_BUCKETS: [...RULE_BUCKETS], summarizeRule, ruleFingerprint, normalizeEventRow, deriveMatchedRuleLabel, formatRiskReasonLabel, fmtNum, fmtTs, classNames }}
          />
        ) : null}
      </main>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(<Shell />);
