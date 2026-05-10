import React, { useEffect, useMemo, useState } from 'react';
import { MetricCard } from '../ui/Cards';

type CoverageGapsPageProps = {
  overview: any;
  policy: any;
  onOpenDecision: (id: number) => void;
  onOpenRules: (draftRule: any) => void;
  helpers: {
    RULE_BUCKETS: readonly string[];
    summarizeRule: (rule: any) => string;
    ruleFingerprint: (rule: any) => string;
    normalizeEventRow: (event: any) => any;
    deriveMatchedRuleLabel: (event: any) => string | null;
    formatRiskReasonLabel: (reason?: string | null) => string;
    fmtNum: (value?: number | null, digits?: number) => string;
    fmtTs: (ts?: number) => string;
    classNames: (...parts: Array<string | false | null | undefined>) => string;
  };
};

function topPairs(values: string[]) {
  const counts = new Map<string, number>();
  for (const value of values || []) {
    if (!value) continue;
    counts.set(value, (counts.get(value) || 0) + 1);
  }
  return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).map(([label, value]) => ({ label, value }));
}

function uniqueSorted(values: string[]) {
  return Array.from(new Set((values || []).filter(Boolean))).sort((a, b) => a.localeCompare(b));
}

function clusterSeverityTone(severity?: string) {
  if (severity === 'critical' || severity === 'high') return 'danger';
  if (severity === 'medium') return 'warn';
  return 'ok';
}

function relativeTimeLabel(ts?: number | null) {
  if (ts === undefined || ts === null || Number.isNaN(Number(ts))) return 'recently';
  const diff = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (diff < 3600) return `${Math.max(1, Math.floor(diff / 60))}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function truncateText(value: string, limit = 24) {
  const text = String(value || '');
  return text.length > limit ? `${text.slice(0, limit - 1)}...` : text;
}

function buildSparklineValues(eventCount: number, gapScore: number) {
  const base = Math.max(10, Math.min(48, Math.round(gapScore / 2)));
  return [base * 0.46, base * 0.62, base * 0.57, base * 0.76, base * 0.68, base * 0.9, base].map((value, idx) =>
    Math.round(value + Math.min(16, eventCount * (0.45 + idx * 0.04)))
  );
}

function buildSuggestedGapRule(cluster: any, event: any) {
  const starter: any = {
    title: truncateText(cluster?.title || 'coverage_gap_rule', 60),
    description: `Drafted from coverage gap: ${cluster?.title || 'uncovered behaviour'}`,
  };
  if (event?.type) starter.type = event.type;
  if (event?.tool) starter.tool = event.tool;
  if (event?.domain) starter['field:domain'] = { contains: event.domain.split('.').slice(-2).join('.') };
  if (event?.risk_score) starter['field:risk_score'] = { gte: Math.max(40, Math.min(85, Math.round(event.risk_score))) };
  for (const [key, value] of Object.entries(event?.classifiers || {})) {
    if (value) starter[`classifier:${key}`] = true;
  }
  if ((event?.method || '').toUpperCase()) starter['field:method'] = { eq: String(event.method).toUpperCase() };
  if ((cluster?.coverageType || '') === 'uncovered' && (event?.classifiers?.internal || event?.classifiers?.pii || event?.classifiers?.secrets)) {
    return { warn: [starter], block: [], monitor: [], allow: [] };
  }
  if ((cluster?.severity || '') === 'critical') {
    return { block: [starter], warn: [], monitor: [], allow: [] };
  }
  return { monitor: [starter], warn: [], block: [], allow: [] };
}

function cloneRule(rule: any) {
  return JSON.parse(JSON.stringify(rule || {}));
}

function buildBucketDraft(bucket: 'monitor' | 'warn' | 'block', starter: any) {
  return {
    block: bucket === 'block' ? [cloneRule(starter)] : [],
    warn: bucket === 'warn' ? [cloneRule(starter)] : [],
    monitor: bucket === 'monitor' ? [cloneRule(starter)] : [],
    allow: [],
  };
}

function buildSuggestedGapRuleVariants(cluster: any, event: any) {
  const base = buildSuggestedGapRule(cluster, event);
  const starter = cloneRule(base.block?.[0] || base.warn?.[0] || base.monitor?.[0] || {});
  const risk = Number(starter?.['field:risk_score']?.gte || 0);
  const monitorStarter = cloneRule(starter);
  if (risk > 0) monitorStarter['field:risk_score'] = { gte: Math.max(30, risk - 15) };
  const warnStarter = cloneRule(starter);
  if (risk > 0) warnStarter['field:risk_score'] = { gte: Math.max(45, risk) };
  const blockStarter = cloneRule(starter);
  if (risk > 0) blockStarter['field:risk_score'] = { gte: Math.max(65, risk + 12) };
  return [
    { id: 'monitor', label: 'Monitor', bucket: 'monitor', guidance: 'Start broad and observe.', draft: buildBucketDraft('monitor', monitorStarter) },
    { id: 'warn', label: 'Warn', bucket: 'warn', guidance: 'Intervene with analyst review.', draft: buildBucketDraft('warn', warnStarter) },
    { id: 'block', label: 'Block', bucket: 'block', guidance: 'Strictest enforcement path.', draft: buildBucketDraft('block', blockStarter) },
  ];
}

function matchRuleOperator(actual: any, expected: any) {
  if (expected === undefined || expected === null || expected === '') return true;
  if (typeof expected !== 'object' || Array.isArray(expected)) return String(actual ?? '') === String(expected);
  if (expected.eq !== undefined) return String(actual ?? '') === String(expected.eq);
  if (expected.contains !== undefined) return String(actual ?? '').toLowerCase().includes(String(expected.contains).toLowerCase());
  if (expected.gte !== undefined) return Number(actual ?? 0) >= Number(expected.gte);
  if (expected.lte !== undefined) return Number(actual ?? 0) <= Number(expected.lte);
  return true;
}

function eventMatchesRuleDraft(ruleDraft: any, event: any) {
  const buckets = ['block', 'warn', 'monitor', 'allow'];
  const rule = buckets.flatMap((bucket) => ruleDraft?.[bucket] || [])[0] || null;
  if (!rule) return false;
  for (const [key, expected] of Object.entries(rule)) {
    if (['title', 'name', 'description', 'reason', 'enabled', 'priority'].includes(key)) continue;
    if (key === 'type' && !matchRuleOperator(event?.type, expected)) return false;
    else if (key === 'tool' && !matchRuleOperator(event?.tool, expected)) return false;
    else if (key === 'field:domain' && !matchRuleOperator(event?.domain, expected)) return false;
    else if (key === 'field:method' && !matchRuleOperator(String(event?.method || '').toUpperCase(), expected)) return false;
    else if (key === 'field:risk_score' && !matchRuleOperator(Number(event?.risk_score || 0), expected)) return false;
    else if (key.startsWith('classifier:')) {
      const classifierKey = key.replace('classifier:', '');
      if (!!event?.classifiers?.[classifierKey] !== !!expected) return false;
    }
  }
  return true;
}

export function CoverageGapsPage({ overview, policy, onOpenDecision, onOpenRules: openRules, helpers }: CoverageGapsPageProps) {
  const { RULE_BUCKETS, summarizeRule, ruleFingerprint, normalizeEventRow, deriveMatchedRuleLabel, formatRiskReasonLabel, fmtNum, fmtTs, classNames } = helpers;
  const [coverageFilter, setCoverageFilter] = useState<'all' | 'uncovered' | 'weak' | 'near'>('all');
  const [timeWindow, setTimeWindow] = useState<'24h' | '7d' | 'all'>('7d');
  const [search, setSearch] = useState('');
  const [eventTypeFilter, setEventTypeFilter] = useState('all');
  const [toolFilter, setToolFilter] = useState('all');
  const [agentFilter, setAgentFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [sortMode, setSortMode] = useState<'gap_score' | 'events' | 'last_seen'>('gap_score');
  const [selectedClusterId, setSelectedClusterId] = useState<string>('');
  const [selectedVariantId, setSelectedVariantId] = useState<string>('monitor');

  const allRules = useMemo(() => {
    const rows: Array<any> = [];
    for (const bucket of RULE_BUCKETS) {
      for (const rule of (policy?.[bucket] || [])) {
        rows.push({ bucket, rule, label: summarizeRule(rule), fingerprint: ruleFingerprint(rule) });
      }
    }
    return rows;
  }, [policy, RULE_BUCKETS, summarizeRule, ruleFingerprint]);

  const sourceEvents = useMemo(() => {
    const deduped = new Map<string, any>();
    const add = (row: any) => {
      if (!row) return;
      const action = row.action || row || {};
      const decision = row.decision || {};
      const normalized = normalizeEventRow(row);
      const event = {
        raw: row,
        id: normalized.id,
        timestamp: Number(row.timestamp || action.timestamp || normalized.timestamp || 0),
        status: normalized.status,
        tool: action.tool || normalized.tool || 'unknown',
        agent: action.agent_name || normalized.agent_name || 'unknown-agent',
        domain: action.domain || normalized.domain || '',
        method: action.method || '',
        type: action.type || row.type || 'tool_call',
        args: action.args || {},
        classifiers: action.classifiers || normalized.classifiers || {},
        risk_score: Number(action.risk_score || normalized.risk_score || 0),
        risk_reasons: action.risk_reasons || [],
        reason: decision.reason || normalized.reason || '',
        matched_label: deriveMatchedRuleLabel(row),
        trace_id: row.trace_id || action.trace_id || normalized.trace_id || '',
        route_target: decision.route_target || action.route_target || normalized.route_target || '',
      };
      const key = event.id ? `id:${event.id}` : `${event.trace_id}:${event.timestamp}:${event.tool}:${event.agent}`;
      deduped.set(key, { ...(deduped.get(key) || {}), ...event });
    };
    for (const row of (overview?.recent_events || [])) add(row);
    for (const trace of (overview?.recent_traces || [])) for (const row of (trace?.events || [])) add(row);
    return Array.from(deduped.values());
  }, [overview, normalizeEventRow, deriveMatchedRuleLabel]);

  const filteredByWindow = useMemo(() => {
    const nowSec = Math.floor(Date.now() / 1000);
    let minTs = 0;
    if (timeWindow === '24h') minTs = nowSec - 86400;
    else if (timeWindow === '7d') minTs = nowSec - (7 * 86400);
    return sourceEvents.filter((event) => !minTs || (event.timestamp || 0) >= minTs);
  }, [sourceEvents, timeWindow]);

  const clusterRows = useMemo(() => {
    const clusters = new Map<string, any>();
    const classifiersToList = (classifiers: Record<string, any>) => Object.entries(classifiers || {}).filter(([, value]) => !!value).map(([key]) => key);
    const nearestRulesForEvent = (event: any) => allRules.map((entry: any) => {
      const rule = entry.rule || {};
      let score = 0;
      if (rule?.type && rule.type === event.type) score += 28;
      if (rule?.tool && rule.tool === event.tool) score += 30;
      if (event.domain && rule?.['field:domain']) score += 15;
      if (event.risk_score > 0 && rule?.['field:risk_score']) score += 12;
      for (const [key, value] of Object.entries(event.classifiers || {})) if (value && rule?.[`classifier:${key}`]) score += 12;
      if ((event.risk_reasons || []).includes('sql_privilege_change') && /sql|database|privilege/i.test(entry.label)) score += 12;
      if ((event.risk_reasons || []).includes('contains_internal_data') && /internal|data|exfil/i.test(entry.label)) score += 10;
      return { ...entry, match: Math.min(95, score) };
    }).filter((row: any) => row.match > 0).sort((a: any, b: any) => b.match - a.match).slice(0, 3);

    for (const event of filteredByWindow) {
      const nearestRules = nearestRulesForEvent(event);
      const top = nearestRules[0]?.match || 0;
      const coverageType = event.matched_label ? 'covered' : top >= 46 ? 'near' : (top >= 24 || event.risk_score >= 55) ? 'weak' : 'uncovered';
      if (coverageType === 'covered') continue;
      const signature = [coverageType, event.type, event.tool, event.method, event.domain ? event.domain.split('.').slice(-2).join('.') : '', Object.keys(event.classifiers || {}).filter((key) => event.classifiers[key]).sort().join('|'), (event.risk_reasons || []).slice().sort().join('|')].join('::');
      const baseScore = Math.min(100, Math.round((event.risk_score * 0.55) + (nearestRules[0]?.match || 0) * 0.18 + ((event.domain && !event.matched_label) ? 12 : 0) + ((event.classifiers?.internal || event.classifiers?.pii || event.classifiers?.secrets) ? 14 : 0) + ((event.risk_reasons || []).includes('sql_privilege_change') ? 16 : 0)));
      const cluster = clusters.get(signature) || { id: signature, title: String(event.tool || event.type || 'activity').replace(/_/g, ' '), summary: event.reason || 'Observed traffic with no direct policy match.', coverageType, severity: baseScore >= 85 ? 'critical' : baseScore >= 70 ? 'high' : baseScore >= 45 ? 'medium' : 'low', gapScore: baseScore, eventCount: 0, agents: new Set<string>(), tools: new Set<string>(), domains: new Set<string>(), eventTypes: new Set<string>(), tags: new Set<string>(), timestamps: [], examples: [], nearestRules, whyUncovered: 'No active rule currently references this tool, route, or classifier combination with enough specificity to match.' };
      cluster.eventCount += 1;
      if (event.agent) cluster.agents.add(event.agent);
      if (event.tool) cluster.tools.add(event.tool);
      if (event.domain) cluster.domains.add(event.domain);
      if (event.type) cluster.eventTypes.add(event.type);
      for (const [key, value] of Object.entries(event.classifiers || {})) if (value) cluster.tags.add(key.replace(/_/g, ' '));
      for (const reason of (event.risk_reasons || []).slice(0, 3)) cluster.tags.add(formatRiskReasonLabel(reason) || reason);
      if (event.timestamp !== undefined && event.timestamp !== null && Number.isFinite(Number(event.timestamp))) cluster.timestamps.push(event.timestamp);
      cluster.examples.push(event);
      cluster.gapScore = Math.min(100, Math.round(Math.max(cluster.gapScore, baseScore) + Math.min(24, cluster.eventCount * 1.8)));
      cluster.severity = cluster.gapScore >= 85 ? 'critical' : cluster.gapScore >= 70 ? 'high' : cluster.gapScore >= 45 ? 'medium' : 'low';
      clusters.set(signature, cluster);
    }

    return Array.from(clusters.values()).map((cluster: any) => {
      const lastSeen = Math.max(...cluster.timestamps, 0);
      const firstSeen = Math.min(...cluster.timestamps, lastSeen || 0);
      const representative = [...cluster.examples].sort((a: any, b: any) => (b.risk_score || 0) - (a.risk_score || 0))[0] || cluster.examples[0] || null;
      return { ...cluster, agents: Array.from(cluster.agents), tools: Array.from(cluster.tools), domains: Array.from(cluster.domains), eventTypes: Array.from(cluster.eventTypes), tags: Array.from(cluster.tags).slice(0, 5), lastSeen, firstSeen, representative, growthHint: cluster.eventCount >= 8 ? `+${Math.min(90, cluster.eventCount * 4)}% in ${timeWindow === '24h' ? '24h' : '3 days'}` : `${cluster.eventCount} recent observations`, suggestedRuleVariants: buildSuggestedGapRuleVariants(cluster, representative) };
    });
  }, [filteredByWindow, allRules, timeWindow, formatRiskReasonLabel]);

  const visibleClusters = useMemo(() => {
    const rows = clusterRows.filter((cluster: any) => {
      if (coverageFilter !== 'all' && cluster.coverageType !== coverageFilter) return false;
      if (search && !JSON.stringify(cluster).toLowerCase().includes(search.toLowerCase())) return false;
      if (eventTypeFilter !== 'all' && !(cluster.eventTypes || []).includes(eventTypeFilter)) return false;
      if (toolFilter !== 'all' && !(cluster.tools || []).includes(toolFilter)) return false;
      if (agentFilter !== 'all' && !(cluster.agents || []).includes(agentFilter)) return false;
      if (severityFilter !== 'all' && cluster.severity !== severityFilter) return false;
      return true;
    });
    rows.sort((a: any, b: any) => sortMode === 'events' ? b.eventCount - a.eventCount : sortMode === 'last_seen' ? (b.lastSeen || 0) - (a.lastSeen || 0) : b.gapScore - a.gapScore);
    return rows;
  }, [clusterRows, coverageFilter, search, eventTypeFilter, toolFilter, agentFilter, severityFilter, sortMode]);

  useEffect(() => {
    if (!selectedClusterId && visibleClusters.length) setSelectedClusterId(visibleClusters[0].id);
    if (selectedClusterId && !visibleClusters.some((cluster: any) => cluster.id === selectedClusterId)) setSelectedClusterId(visibleClusters[0]?.id || '');
  }, [visibleClusters, selectedClusterId]);

  const selectedCluster = visibleClusters.find((cluster: any) => cluster.id === selectedClusterId) || visibleClusters[0] || null;
  const selectedVariant = useMemo(() => {
    const variants = selectedCluster?.suggestedRuleVariants || [];
    return variants.find((variant: any) => variant.id === selectedVariantId) || variants[0] || null;
  }, [selectedCluster, selectedVariantId]);
  const variantImpacts = useMemo(() => {
    const variants = selectedCluster?.suggestedRuleVariants || [];
    const clusterEvents = selectedCluster?.examples || [];
    return variants.map((variant: any) => {
      const totalMatched = filteredByWindow.filter((event: any) => eventMatchesRuleDraft(variant.draft, event)).length;
      const clusterMatched = clusterEvents.filter((event: any) => eventMatchesRuleDraft(variant.draft, event)).length;
      return { ...variant, totalMatched, clusterMatched };
    });
  }, [selectedCluster, filteredByWindow]);
  useEffect(() => {
    if (!selectedCluster) return;
    const variants = selectedCluster.suggestedRuleVariants || [];
    if (!variants.length) return;
    if (!variants.some((variant: any) => variant.id === selectedVariantId)) setSelectedVariantId(variants[0].id);
  }, [selectedCluster, selectedVariantId]);
  const onOpenRules = () => { if (selectedVariant?.draft) openRules(selectedVariant.draft); };
  const totals = useMemo(() => {
    const uncoveredEvents = visibleClusters.reduce((sum: number, cluster: any) => sum + cluster.eventCount, 0);
    const highPriority = visibleClusters.filter((cluster: any) => cluster.gapScore >= 75).length;
    const byCoverage = { uncovered: visibleClusters.filter((cluster: any) => cluster.coverageType === 'uncovered').length, weak: visibleClusters.filter((cluster: any) => cluster.coverageType === 'weak').length, near: visibleClusters.filter((cluster: any) => cluster.coverageType === 'near').length };
    const fastest = [...visibleClusters].sort((a: any, b: any) => b.eventCount - a.eventCount)[0] || null;
    const topTool = topPairs(visibleClusters.flatMap((cluster: any) => cluster.tools || []))[0] || null;
    const topAgent = topPairs(visibleClusters.flatMap((cluster: any) => cluster.agents || []))[0] || null;
    return { uncoveredEvents, highPriority, byCoverage, fastest, topTool, topAgent };
  }, [visibleClusters]);
  const eventTypeOptions = useMemo(() => uniqueSorted(visibleClusters.flatMap((cluster: any) => cluster.eventTypes || [])), [visibleClusters]);
  const toolOptions = useMemo(() => uniqueSorted(visibleClusters.flatMap((cluster: any) => cluster.tools || [])), [visibleClusters]);
  const agentOptions = useMemo(() => uniqueSorted(visibleClusters.flatMap((cluster: any) => cluster.agents || [])), [visibleClusters]);

  return (
    <section className="pageGrid">
      <div className="metricsRow metricsRow--six">
        <MetricCard title="Uncovered Events" value={fmtNum(totals.uncoveredEvents)} subtitle={`${fmtNum(sourceEvents.length ? (totals.uncoveredEvents / sourceEvents.length) * 100 : 0, 1)}% of recent observed traffic`} tone="warn" />
        <MetricCard title="Gap Clusters" value={fmtNum(visibleClusters.length)} subtitle={`${fmtNum(totals.highPriority)} high-priority clusters`} tone="accent" />
        <MetricCard title="High-Priority Gaps" value={fmtNum(totals.highPriority)} subtitle="Require active policy attention" tone="danger" />
        <MetricCard title="Fastest Growing" value={totals.fastest ? truncateText(totals.fastest.title, 22) : '—'} subtitle={totals.fastest ? totals.fastest.growthHint : 'No gap growth observed'} tone="warn" />
        <MetricCard title="Most Frequent Tool" value={totals.topTool?.label || '—'} subtitle={totals.topTool ? `${totals.topTool.value} clusters` : 'No uncovered tool activity'} tone="ok" />
        <MetricCard title="Most Exposed Agent" value={totals.topAgent?.label || '—'} subtitle={totals.topAgent ? `${totals.topAgent.value} clusters` : 'No exposed agent found'} tone="accent" />
      </div>
      <div className="card coverageToolbar">{/* unchanged UI controls */}
        <div className="coverageToolbar__left"><div className="toggleRow">{[['all', `All gaps ${visibleClusters.length}`], ['uncovered', `Uncovered ${totals.byCoverage.uncovered}`], ['weak', `Weak coverage ${totals.byCoverage.weak}`], ['near', `Near existing rule ${totals.byCoverage.near}`]].map(([value, label]) => (<button key={value} className={classNames('segmented', coverageFilter === value && 'is-active')} onClick={() => setCoverageFilter(value as any)}>{label}</button>))}</div><input className="input coverageToolbar__search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search clusters..." /></div>
        <div className="coverageToolbar__right"><select className="input input--small" value={eventTypeFilter} onChange={(e) => setEventTypeFilter(e.target.value)}><option value="all">Event Type</option>{eventTypeOptions.map((value) => <option key={value} value={value}>{value}</option>)}</select><select className="input input--small" value={toolFilter} onChange={(e) => setToolFilter(e.target.value)}><option value="all">Tool</option>{toolOptions.map((value) => <option key={value} value={value}>{value}</option>)}</select><select className="input input--small" value={agentFilter} onChange={(e) => setAgentFilter(e.target.value)}><option value="all">Agent</option>{agentOptions.map((value) => <option key={value} value={value}>{value}</option>)}</select><select className="input input--small" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}><option value="all">Severity</option>{['critical', 'high', 'medium', 'low'].map((value) => <option key={value} value={value}>{value}</option>)}</select><select className="input input--small" value={sortMode} onChange={(e) => setSortMode(e.target.value as any)}><option value="gap_score">Sort: Gap score</option><option value="events">Sort: Events</option><option value="last_seen">Sort: Last seen</option></select><select className="input input--small" value={timeWindow} onChange={(e) => setTimeWindow(e.target.value as any)}><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="all">All recent data</option></select></div>
      </div>
      {visibleClusters.length ? <div className="coverageLayout"><div className="card"><div className="sectionHeader"><div><div className="eyebrow">Gap cluster</div><h3>Top coverage gaps</h3></div><div className="muted">Observed behaviours with little or no active policy coverage.</div></div><div className="coverageList">{visibleClusters.map((cluster: any) => (<button key={cluster.id} type="button" className={classNames('coverageCluster', selectedCluster?.id === cluster.id && 'is-active')} onClick={() => setSelectedClusterId(cluster.id)}><div className={classNames('coverageCluster__icon', `is-${clusterSeverityTone(cluster.severity)}`)} /><div className="coverageCluster__body"><div className="coverageCluster__headline"><div><strong>{cluster.title}</strong><p>{cluster.summary}</p></div><div className="coverageCluster__score">{cluster.gapScore}</div></div><div className="coverageCluster__meta"><span>{fmtNum(cluster.eventCount)} events</span><span>{fmtNum(cluster.agents.length)} agents</span><span>{cluster.lastSeen ? `Last seen ${relativeTimeLabel(cluster.lastSeen)}` : 'Last seen —'}</span></div><div className="coverageCluster__chips"><span className={classNames('badge', `badge--${clusterSeverityTone(cluster.severity)}`)}>{cluster.severity}</span><span className={classNames('badge', cluster.coverageType === 'uncovered' ? 'badge--danger' : cluster.coverageType === 'weak' ? 'badge--warn' : 'badge--ok')}>{cluster.coverageType === 'near' ? 'near rule' : cluster.coverageType}</span>{cluster.tags.map((tag: string) => <span key={tag} className="badge">{truncateText(tag, 28)}</span>)}</div><div className="coverageCluster__impact"><div className="coverageCluster__heat"><div style={{ width: `${cluster.gapScore}%` }} /></div><span>{cluster.growthHint}</span></div></div></button>))}</div></div><div className="card coverageDetail">{selectedCluster ? <><div className="coverageDetail__header"><div><div className="coverageDetail__titleRow"><h3>{selectedCluster.title}</h3><span className={classNames('badge', selectedCluster.coverageType === 'uncovered' ? 'badge--danger' : selectedCluster.coverageType === 'weak' ? 'badge--warn' : 'badge--ok')}>{selectedCluster.coverageType === 'near' ? 'Near existing rule' : selectedCluster.coverageType}</span></div><div className="traceCard__meta">First seen {fmtTs(selectedCluster.firstSeen)} · Last seen {fmtTs(selectedCluster.lastSeen)} · {fmtNum(selectedCluster.eventCount)} events · {fmtNum(selectedCluster.agents.length)} agents</div></div><div className="coverageDetail__scoreRing"><span>{selectedCluster.gapScore}</span></div></div><div className="coverageDetailGrid"><div className="coverageInfoCard"><div className="subheading">Why this is uncovered</div><p className="muted">{selectedCluster.whyUncovered}</p><div className="subheading" style={{ marginTop: 16 }}>Nearest existing rules</div><div className="coverageNearestList">{selectedCluster.nearestRules.length ? selectedCluster.nearestRules.map((row: any) => (<div key={`${row.fingerprint}:${row.match}`} className="coverageNearestItem"><div><strong>{row.label}</strong><div className="traceCard__meta">{row.bucket} policy bucket</div></div><span className="badge">{row.match}% match</span></div>)) : <div className="muted">No adjacent rule concepts were found.</div>}</div><div className="subheading" style={{ marginTop: 16 }}>Suggested policy variants</div><div className="toggleRow" style={{ marginTop: 8, marginBottom: 10 }}>{variantImpacts.map((variant: any) => (<button key={variant.id} type="button" className={classNames('segmented', selectedVariant?.id === variant.id && 'is-active')} onClick={() => setSelectedVariantId(variant.id)}>{variant.label}</button>))}</div><div className="coverageCluster__chips" style={{ marginBottom: 12 }}>{variantImpacts.map((variant: any) => (<span key={`${variant.id}-impact`} className={classNames('badge', selectedVariant?.id === variant.id && 'badge--ok')}>{variant.label}: {fmtNum(variant.clusterMatched)}/{fmtNum(selectedCluster.eventCount)} in cluster · {fmtNum(variant.totalMatched)}/{fmtNum(filteredByWindow.length)} total</span>))}</div><div className="traceCard__meta" style={{ marginBottom: 10 }}>{selectedVariant?.guidance || ''}</div><div className="codeCard coverageCodeCard"><pre>{JSON.stringify(selectedVariant?.draft || {}, null, 2)}</pre></div><div className="coverageActionRow"><button type="button" className="button" onClick={onOpenRules} disabled={!selectedVariant?.draft}>Create draft rule</button>{selectedCluster.representative?.id ? <button type="button" className="button button--ghost" onClick={() => onOpenDecision(selectedCluster.representative.id)}>Open this event in decision view</button> : null}</div></div><div className="coverageInfoCard"><div className="subheading">Representative sample</div>{selectedCluster.representative ? <div className="coverageSample"><div className="coverageSample__row"><span>Agent</span><strong>{selectedCluster.representative.agent}</strong></div><div className="coverageSample__row"><span>Tool</span><strong>{selectedCluster.representative.tool}</strong></div><div className="coverageSample__row"><span>Type</span><strong>{selectedCluster.representative.type}</strong></div><div className="coverageSample__row"><span>Domain</span><strong>{selectedCluster.representative.domain || '—'}</strong></div><div className="coverageSample__row"><span>Route</span><strong>{selectedCluster.representative.route_target || '—'}</strong></div><div className="coverageSample__row"><span>Risk</span><strong>{fmtNum(selectedCluster.representative.risk_score)}</strong></div><div className="coverageSample__chips">{(Object.entries(selectedCluster.representative.classifiers || {}).filter(([, value]) => !!value).map(([key]) => key)).slice(0, 6).map((key) => (<span key={key} className="badge">{key.replace(/_/g, ' ')}</span>))}</div><div className="coverageSummaryGrid" style={{ marginTop: 12 }}><div className="coverageMiniCard"><div className="subheading">Top agents</div>{topPairs(selectedCluster.agents).slice(0, 4).map((row: any) => <div key={row.label} className="coverageMiniCard__row"><span>{row.label}</span><strong>{row.value}</strong></div>)}</div><div className="coverageMiniCard"><div className="subheading">Top tools</div>{topPairs(selectedCluster.tools).slice(0, 4).map((row: any) => <div key={row.label} className="coverageMiniCard__row"><span>{row.label}</span><strong>{row.value}</strong></div>)}</div><div className="coverageMiniCard"><div className="subheading">Top domains</div>{topPairs(selectedCluster.domains).slice(0, 4).map((row: any) => <div key={row.label} className="coverageMiniCard__row"><span>{truncateText(row.label, 24)}</span><strong>{row.value}</strong></div>)}</div><div className="coverageMiniCard"><div className="subheading">Trend</div><div className="coverageTrend__spark">{buildSparklineValues(selectedCluster.eventCount, selectedCluster.gapScore).map((value: number, idx: number) => (<span key={idx} style={{ height: `${Math.max(14, value)}px` }} />))}</div><div className="traceCard__meta">{selectedCluster.growthHint}</div></div></div></div> : <div className="muted">No sample event available.</div>}</div></div></> : <div className="emptyState"><strong>No cluster selected.</strong><span className="muted">Choose a gap cluster from the list to inspect coverage blind spots and draft the next policy.</span></div>}</div></div> : <div className="card coverageEmptyCard"><div className="sectionHeader"><div><div className="eyebrow">Gap cluster</div><h3>Top coverage gaps</h3></div><div className="muted">Observed behaviours with little or no active policy coverage.</div></div><div className="emptyState coverageEmptyState"><strong>No coverage gaps in this view.</strong><span className="muted">Try widening the time window or clearing filters.</span></div></div>}
    </section>
  );
}
