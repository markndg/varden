import React, { useEffect, useMemo, useState } from 'react';

type ImpactPageProps = {
  overview: any;
  policy: any;
  onOpenDecision: (id: number) => void;
  onOpenRules: (bucket: string, label: string, token?: string, index?: number) => void;
  helpers: {
    RULE_BUCKETS: readonly string[];
    pickFirstNonEmptyBucket: (policy: any) => any;
    ensurePolicyDoc: (doc: any) => any;
    dedupePolicyDoc: (doc: any) => any;
    normalizeEventRow: (row: any) => any;
    summarizeRule: (rule: any) => string;
    summarizeRuleConditions: (rule: any, max?: number) => string[];
    deriveMatchedRuleLabel: (event: any) => string | null;
    semanticRuleFingerprint: (rule: any) => string;
    formatRuleFieldLabel: (field?: string | null) => string;
    bucketTone: (bucket: string) => string;
    classNames: (...parts: Array<string | false | null | undefined>) => string;
    fmtNum: (value?: number | null, digits?: number) => string;
    statusTone: (status: string) => string;
    eventOutcomeStatus: (event: any) => string;
  };
};

export function ImpactPage({ overview, policy, onOpenDecision, onOpenRules, helpers }: ImpactPageProps) {
  const { RULE_BUCKETS, pickFirstNonEmptyBucket, ensurePolicyDoc, dedupePolicyDoc, normalizeEventRow, summarizeRule, summarizeRuleConditions, deriveMatchedRuleLabel, semanticRuleFingerprint, formatRuleFieldLabel, bucketTone, classNames, fmtNum, statusTone, eventOutcomeStatus } = helpers;
  const [activeBucket, setActiveBucket] = useState<typeof RULE_BUCKETS[number]>(pickFirstNonEmptyBucket(ensurePolicyDoc(policy)));
  const [windowMode, setWindowMode] = useState<'recent' | 'all'>('recent');
  const [analyticsMode, setAnalyticsMode] = useState<'impact' | 'detections' | 'fp'>('impact');
  const [selectedRuleId, setSelectedRuleId] = useState<string>('');

  const policyDoc = useMemo(() => dedupePolicyDoc(ensurePolicyDoc(policy)), [policy, dedupePolicyDoc, ensurePolicyDoc]);

  useEffect(() => {
    const available = (policyDoc[activeBucket] || []).length > 0;
    if (!available) setActiveBucket(pickFirstNonEmptyBucket(policyDoc));
  }, [policyDoc, activeBucket, pickFirstNonEmptyBucket]);

  const sourceEvents = useMemo(() => {
    const merged = new Map<number, any>();
    for (const row of (overview?.recent_events || []).map(normalizeEventRow)) {
      if (row.id) merged.set(row.id, row as any);
    }
    for (const trace of (overview?.recent_traces || [])) {
      for (const row of (trace?.events || []).map(normalizeEventRow)) {
        if (row.id) merged.set(row.id, { ...(merged.get(row.id) || {}), ...(row as any) });
      }
    }
    return Array.from(merged.values()).sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
  }, [overview, normalizeEventRow]);

  const filteredEvents = useMemo(() => {
    if (windowMode === 'all') return sourceEvents;
    const latestTs = Math.max(...sourceEvents.map((event) => Number(event.timestamp || 0)), 0);
    const cutoff = latestTs ? latestTs - (24 * 60 * 60) : 0;
    return sourceEvents.filter((event) => Number(event.timestamp || 0) >= cutoff);
  }, [sourceEvents, windowMode]);

  const ruleRows = useMemo(() => {
    const totalEvents = Math.max(filteredEvents.length, 1);
    const lower = (value: any) => String(value || '').trim().toLowerCase();
    const toDayKey = (ts?: number | null) => {
      if (ts === undefined || ts === null || Number.isNaN(Number(ts))) return 'Unknown';
      const dt = new Date(ts * 1000);
      return `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, '0')}-${String(dt.getDate()).padStart(2, '0')}`;
    };
    const daySeries = (() => {
      const latestTs = Math.max(...filteredEvents.map((event) => Number(event.timestamp || 0)), 0);
      const end = latestTs ? new Date(latestTs * 1000) : new Date();
      const out: string[] = [];
      for (let i = 6; i >= 0; i -= 1) {
        const dt = new Date(end);
        dt.setDate(end.getDate() - i);
        out.push(`${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, '0')}-${String(dt.getDate()).padStart(2, '0')}`);
      }
      return out;
    })();
    const deriveTags = (rule: any) => {
      const tags = new Set<string>();
      if (rule?.type) tags.add(String(rule.type));
      if (rule?.tool) tags.add(String(rule.tool));
      for (const [key, value] of Object.entries(rule || {})) {
        if (String(key).startsWith('classifier:') && value) tags.add(String(key).replace('classifier:', ''));
        if (String(key).startsWith('field:') && String(key) !== 'field:risk_score') tags.add(formatRuleFieldLabel(String(key)));
      }
      return Array.from(tags).slice(0, 4);
    };

    const eventRuleToken = (event: any) => {
      const matchedRule = event?.matched_rule || event?.decision?.matched_rule;
      if (!matchedRule || typeof matchedRule !== 'object') return '';
      return semanticRuleFingerprint(matchedRule);
    };

    return RULE_BUCKETS.flatMap((bucket) => (policyDoc[bucket] || []).map((rule: any, index: number) => {
      const summary = summarizeRule(rule);
      const summaryLc = lower(summary);
      const reasonLc = lower(rule?.description || rule?.reason || '');
      const toolLc = lower(rule?.tool || '');
      const tags = deriveTags(rule);
      const conditionSummary = summarizeRuleConditions(rule, 3);
      const matches = filteredEvents.filter((event: any) => {
        const label = lower((event as any).matched_rule_label || deriveMatchedRuleLabel(event) || '');
        const reason = lower(event?.reason || '');
        const outcome = event.outcome || eventOutcomeStatus(event);
        const bucketMatches = bucket === 'allow' ? outcome === 'allowed' : bucket === 'warn' ? outcome === 'warned' : bucket === 'block' ? outcome === 'blocked' : true;
        if (label && summaryLc && (label === summaryLc || label.includes(summaryLc) || summaryLc.includes(label))) return true;
        if (reasonLc && reason.includes(reasonLc) && bucketMatches) return true;
        if (toolLc && lower(event.tool).includes(toolLc) && bucketMatches && (outcome === 'blocked' || outcome === 'warned')) return true;
        if (bucket === 'allow' && !label && outcome === 'allowed' && toolLc && lower(event.tool).includes(toolLc)) return true;
        return false;
      });
      const exactToken = semanticRuleFingerprint(rule);
      const strictMatches = matches.filter((event: any) => {
        const token = eventRuleToken(event);
        return token && token === exactToken;
      });
      const effectiveMatches = strictMatches.length ? strictMatches : matches;

      const detections = effectiveMatches.length;
      const blocked = effectiveMatches.filter((event) => (event.outcome || eventOutcomeStatus(event)) === 'blocked').length;
      const warned = effectiveMatches.filter((event) => (event.outcome || eventOutcomeStatus(event)) === 'warned').length;
      const allowed = effectiveMatches.filter((event) => (event.outcome || eventOutcomeStatus(event)) === 'allowed').length;
      const impactScore = blocked * 1 + warned * 0.65 + allowed * 0.2;
      const coverage = detections ? (detections / totalEvents) * 100 : 0;
      const lowRiskHits = effectiveMatches.filter((event) => Number(event.risk_score || 0) <= 20).length;
      const localhostHits = effectiveMatches.filter((event) => String(event.domain || '').includes('localhost') || String(event.domain || '').endsWith('.local')).length;
      const falsePositiveRate = detections ? ((lowRiskHits + localhostHits * 0.5) / detections) * 100 : 0;
      const topAgents = Object.entries(effectiveMatches.reduce((acc: Record<string, number>, event: any) => { const key = event.agent_name || 'unknown'; acc[key] = (acc[key] || 0) + 1; return acc; }, {})).sort((a: any, b: any) => b[1] - a[1]).slice(0, 5);
      const topTools = Object.entries(effectiveMatches.reduce((acc: Record<string, number>, event: any) => { const key = event.tool || 'unknown'; acc[key] = (acc[key] || 0) + 1; return acc; }, {})).sort((a: any, b: any) => b[1] - a[1]).slice(0, 5);
      const topDomains = Object.entries(effectiveMatches.reduce((acc: Record<string, number>, event: any) => { const key = event.domain || 'local'; acc[key] = (acc[key] || 0) + 1; return acc; }, {})).sort((a: any, b: any) => b[1] - a[1]).slice(0, 5);
      const timelineMap = new Map<string, number>();
      daySeries.forEach((day) => timelineMap.set(day, 0));
      effectiveMatches.forEach((event) => { const key = toDayKey(event.timestamp); timelineMap.set(key, (timelineMap.get(key) || 0) + 1); });
      const recentEvents = effectiveMatches.slice(0, 6);
      const falsePositiveCandidates = effectiveMatches.filter((event: any) => Number(event.risk_score || 0) <= 20 || String(event.domain || '').includes('localhost')).slice(0, 4);
      const id = `${bucket}:${index}:${semanticRuleFingerprint(rule)}`;
      return { id, bucket, index, rule, label: summary, detections, blocked, warned, allowed, impactScore, coverage, falsePositiveRate, tags, conditionSummary, exactToken, topAgents, topTools, topDomains, timeline: Array.from(timelineMap.entries()).map(([day, count]) => ({ day, count })), recentEvents, falsePositiveCandidates, enabled: rule?.enabled !== false };
    }));
  }, [RULE_BUCKETS, policyDoc, filteredEvents, summarizeRule, summarizeRuleConditions, deriveMatchedRuleLabel, eventOutcomeStatus, formatRuleFieldLabel, semanticRuleFingerprint]);

  const bucketCounts = useMemo(() => RULE_BUCKETS.reduce((acc: Record<string, number>, bucket) => { acc[bucket] = (policyDoc[bucket] || []).length; return acc; }, {} as Record<string, number>), [RULE_BUCKETS, policyDoc]);
  const bucketRows = useMemo(() => {
    const rows = ruleRows.filter((row: any) => row.bucket === activeBucket);
    const sorter = analyticsMode === 'detections' ? (left: any, right: any) => right.detections - left.detections : analyticsMode === 'fp' ? (left: any, right: any) => right.falsePositiveRate - left.falsePositiveRate : (left: any, right: any) => right.impactScore - left.impactScore;
    return [...rows].sort(sorter);
  }, [ruleRows, activeBucket, analyticsMode]);

  useEffect(() => {
    if (!bucketRows.length) { setSelectedRuleId(''); return; }
    if (!bucketRows.some((row: any) => row.id === selectedRuleId)) setSelectedRuleId(bucketRows[0].id);
  }, [bucketRows, selectedRuleId]);

  const selectedRow = bucketRows.find((row: any) => row.id === selectedRuleId) || bucketRows[0] || null;
  const maxBucketValue = Math.max(...bucketRows.map((row: any) => analyticsMode === 'detections' ? row.detections : analyticsMode === 'fp' ? row.falsePositiveRate : row.impactScore), 1);
  const allDetections = bucketRows.reduce((sum: number, row: any) => sum + row.detections, 0);
  const activeRules = bucketRows.filter((row: any) => row.detections > 0).length;
  const selectedFalsePositiveRate = Math.max(0, Math.min(100, Number(selectedRow?.falsePositiveRate || 0)));
  const donutStyle = { background: `conic-gradient(rgba(255,191,90,.95) 0 ${selectedFalsePositiveRate}%, rgba(255,255,255,.08) ${selectedFalsePositiveRate}% 100%)` };

  return (
    <div className="pageGrid impactPage">
      <section className="layout layout--impact">
        <div className="card impactCard">
          <div className="sectionHeader">
            <div>
              <div className="eyebrow">Live policy impact</div>
              <h3>Heatmap of live policy impact</h3>
              <p className="muted">See which rules are carrying the heaviest load across your observed traffic. Click a rule to inspect who it affects and where it fires.</p>
            </div>
            <div className="toggleRow">
              <div className="toggleRow">
                <button type="button" className={classNames('segmented', windowMode === 'recent' && 'is-active')} onClick={() => setWindowMode('recent')}>Last 24h</button>
                <button type="button" className={classNames('segmented', windowMode === 'all' && 'is-active')} onClick={() => setWindowMode('all')}>All loaded</button>
              </div>
              <div className="toggleRow">
                <button type="button" className={classNames('segmented', analyticsMode === 'impact' && 'is-active')} onClick={() => setAnalyticsMode('impact')}>Impact</button>
                <button type="button" className={classNames('segmented', analyticsMode === 'detections' && 'is-active')} onClick={() => setAnalyticsMode('detections')}>Detections</button>
                <button type="button" className={classNames('segmented', analyticsMode === 'fp' && 'is-active')} onClick={() => setAnalyticsMode('fp')}>False positive</button>
              </div>
            </div>
          </div>
          <div className="bucketTabs impactBucketTabs">
            {RULE_BUCKETS.map((bucket) => (
              <button type="button" key={bucket} className={classNames('bucketTab', activeBucket === bucket && 'is-active')} onClick={() => setActiveBucket(bucket)}>
                <span>{bucket}</span>
                <strong>{bucketCounts[bucket] || 0}</strong>
              </button>
            ))}
          </div>
          <div className="impactSummaryRow">
            <div className="bucketCard"><span>Visible rules</span><strong>{bucketRows.length}</strong></div>
            <div className="bucketCard"><span>Active rules</span><strong>{activeRules}</strong></div>
            <div className="bucketCard"><span>Detections</span><strong>{allDetections}</strong></div>
            <div className="bucketCard"><span>Mode</span><strong>{analyticsMode}</strong></div>
          </div>
          <div className="impactTable">
            <div className="impactTable__header"><span>Rule</span><span>Annotations</span><span>{analyticsMode === 'impact' ? 'Impact' : analyticsMode === 'detections' ? 'Detections' : 'False positive'}</span><span>Coverage</span><span>Enabled</span><span>False positive</span></div>
            <div className="impactTable__body">
              {bucketRows.length ? bucketRows.map((row: any) => {
                const heatValue = analyticsMode === 'detections' ? row.detections : analyticsMode === 'fp' ? row.falsePositiveRate : row.impactScore;
                const heatWidth = `${Math.max(8, (heatValue / maxBucketValue) * 100)}%`;
                return (
                  <button key={row.id} type="button" className={classNames('impactRow', selectedRow?.id === row.id && 'is-active')} onClick={() => setSelectedRuleId(row.id)}>
                    <div className="impactRow__rule"><span className={`badge badge--${bucketTone(row.bucket)}`}>{row.bucket}</span><div><div className="impactRow__title">{row.label}</div><div className="impactRow__meta">{row.rule?.type || 'any type'} {row.rule?.tool ? `· ${row.rule.tool}` : ''}</div>{row.conditionSummary?.length ? <div className="impactRow__detail">{row.conditionSummary.join(' · ')}</div> : null}</div></div>
                    <div className="impactRow__tags">{row.tags.length ? row.tags.map((tag: string) => <span key={tag} className="badge">{tag}</span>) : <span className="muted">No annotations</span>}</div>
                    <div className="impactHeat"><div className="impactHeat__bar"><div className="impactHeat__fill" style={{ width: heatWidth }} /></div><strong>{analyticsMode === 'fp' ? `${fmtNum(row.falsePositiveRate, 1)}%` : analyticsMode === 'impact' ? fmtNum(row.impactScore, 1) : row.detections}</strong></div>
                    <div className="impactRow__coverage">{fmtNum(row.coverage, 1)}%</div>
                    <div className="impactToggleCell">{row.enabled ? <span className="toggleBadge toggleBadge--on">On</span> : <span className="toggleBadge">Off</span>}</div>
                    <div className="impactRow__fp">{fmtNum(row.falsePositiveRate, 1)}%</div>
                  </button>
                );
              }) : <div className="emptyState"><strong>No {activeBucket} rules yet</strong><span className="muted">Create or import rules in this bucket to see impact analysis here.</span></div>}
            </div>
          </div>
        </div>
        <div className="card impactDrilldown">
          {selectedRow ? (
            <>
              <div className="sectionHeader"><div><div className="eyebrow">Rule drilldown</div><h3>{selectedRow.label}</h3><p className="muted">{selectedRow.rule?.description || selectedRow.rule?.reason || 'No rule description yet.'}</p></div><div className={`badge badge--${bucketTone(selectedRow.bucket)}`}>{selectedRow.bucket}</div></div>
              <div className="impactDrilldown__stats"><div className="metricCard metricCard--danger"><div className="metricCard__title">Blocked</div><div className="metricCard__value">{selectedRow.blocked}</div><div className="metricCard__subtitle">hard stops</div></div><div className="metricCard metricCard--warn"><div className="metricCard__title">Warned</div><div className="metricCard__value">{selectedRow.warned}</div><div className="metricCard__subtitle">needs review</div></div><div className="metricCard metricCard--ok"><div className="metricCard__title">Allowed</div><div className="metricCard__value">{selectedRow.allowed}</div><div className="metricCard__subtitle">passed through</div></div></div>
              <div className="impactDrilldown__donutRow"><div className="impactDonut" style={donutStyle}><div className="impactDonut__inner"><strong>{fmtNum(selectedFalsePositiveRate, 0)}%</strong><span>FP proxy</span></div></div><div className="stack"><div className="subheading">What this rule is touching</div><div className="traceSummaryBar"><span>{selectedRow.detections} detections</span><span>{fmtNum(selectedRow.coverage, 1)}% coverage</span><span>{fmtNum(selectedRow.impactScore, 1)} weighted impact</span></div><div className="impactActions"><button type="button" className="button" onClick={() => onOpenRules(selectedRow.bucket, selectedRow.label, selectedRow.exactToken, selectedRow.index)}>Open in rules workspace</button>{selectedRow.recentEvents[0]?.id ? <button type="button" className="button button--ghost" onClick={() => onOpenDecision(selectedRow.recentEvents[0].id)}>Open latest decision</button> : null}</div></div></div>
              <div className="impactTrendCard"><div className="subheading">Recent trend</div><div className="impactTrend">{selectedRow.timeline.map((point: any) => { const max = Math.max(...selectedRow.timeline.map((entry: any) => entry.count), 1); const height = Math.max(10, (point.count / max) * 100); return (<div key={point.day} className="impactTrend__barWrap" title={`${point.day} · ${point.count} hits`}><div className="impactTrend__bar" style={{ height: `${height}%` }} /><span>{point.day.slice(5)}</span></div>); })}</div></div>
              <div className="layout layout--impactLists"><div className="impactListCard"><div className="subheading">Top agents</div><div className="barList">{selectedRow.topAgents.map(([label, value]: any) => (<div key={label} className="barList__row"><span>{label}</span><div className="barList__track"><div className="barList__fill" style={{ width: `${(value / Math.max(selectedRow.topAgents[0]?.[1] || 1, 1)) * 100}%` }} /></div><strong>{value}</strong></div>))}</div></div><div className="impactListCard"><div className="subheading">Top tools</div><div className="barList">{selectedRow.topTools.map(([label, value]: any) => (<div key={label} className="barList__row"><span>{label}</span><div className="barList__track"><div className="barList__fill" style={{ width: `${(value / Math.max(selectedRow.topTools[0]?.[1] || 1, 1)) * 100}%` }} /></div><strong>{value}</strong></div>))}</div></div></div>
              <div className="impactListCard"><div className="subheading">Top domains</div><div className="barList">{selectedRow.topDomains.map(([label, value]: any) => (<div key={label} className="barList__row"><span>{label}</span><div className="barList__track"><div className="barList__fill" style={{ width: `${(value / Math.max(selectedRow.topDomains[0]?.[1] || 1, 1)) * 100}%` }} /></div><strong>{value}</strong></div>))}</div></div>
              <div className="impactListCard"><div className="subheading">False positive candidates</div><div className="eventRail">{selectedRow.falsePositiveCandidates.length ? selectedRow.falsePositiveCandidates.map((event: any) => (<button key={event.id} type="button" className="eventRow" onClick={() => onOpenDecision(event.id)}><div className={classNames('eventRow__dot', `is-${statusTone(event.outcome || eventOutcomeStatus(event))}`)} /><div className="eventRow__main"><div className="eventRow__title">{event.tool || 'event'} <span className={`badge badge--${statusTone(event.outcome || eventOutcomeStatus(event))}`}>{event.outcome || eventOutcomeStatus(event)}</span></div><div className="eventRow__meta">{event.agent_name || 'unknown'} · {event.domain || 'local'} · risk {event.risk_score || 0}</div></div><div className="eventRow__score">{event.id}</div></button>)) : <div className="emptyState emptyState--compact"><strong>No false positive candidates surfaced</strong><span className="muted">Once operator feedback exists, this section can be upgraded from proxy to confirmed false positives.</span></div>}</div></div>
            </>
          ) : <div className="emptyState"><strong>No rule selected</strong><span className="muted">Choose a rule from the heatmap to inspect its blast radius.</span></div>}
        </div>
      </section>
    </div>
  );
}
