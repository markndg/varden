import React from 'react';

type TraceGraphProps = {
  trace: any;
  compact?: boolean;
  onOpenDecision: (id: number) => void;
  onOpenRule: (label: string, bucket?: string) => void;
  helpers: {
    eventOutcomeStatus: (event: any) => string;
    statusTone: (status: string) => string;
    deriveMatchedRuleLabel: (event: any) => string | null;
    deriveRuleLabelFromRuleObject: (rule: any, fallbackStatus?: string) => string | null;
    normalizeEventRow: (event: any) => any;
    eventRuleBucket: (event: any) => string;
    fmtTs: (ts?: number) => string;
    displayValue: (value: any) => string;
  };
};

export function TraceGraph({ trace, onOpenDecision, onOpenRule, compact, helpers }: TraceGraphProps) {
  const { eventOutcomeStatus, statusTone, deriveMatchedRuleLabel, deriveRuleLabelFromRuleObject, normalizeEventRow, eventRuleBucket, fmtTs, displayValue } = helpers;
  if (!trace?.graph?.nodes?.length && !(compact && trace?.events?.length)) return <div className="traceEmpty">No trace selected yet.</div>;
  const nodes = trace.graph?.nodes || [];
  const width = Math.max(920, nodes.length * 220);
  const height = compact ? 320 : 420;
  const laneY = compact ? 110 : 138;
  const eventPositions = nodes.map((node: any, index: number) => ({ ...node, x: 80 + (index * 210), y: laneY }));
  const byId = new Map<any, any>(eventPositions.map((node: any) => [node.id, node]));
  const eventMap = new Map<any, any>((trace.events || []).map((event: any) => [event.id, event]));
  const ruleNodes = eventPositions.flatMap((node: any, index: number) => {
    const event = eventMap.get(node.id);
    const matchedRule = event?.decision?.matched_rule;
    if (!matchedRule) return [];
    const outcome = eventOutcomeStatus(event || node);
    const label = deriveMatchedRuleLabel(event) || deriveRuleLabelFromRuleObject(matchedRule, outcome) || 'Triggered rule';
    const severity = statusTone(outcome);
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
    const steps = (trace.events || []).map((event: any) => normalizeEventRow(event)).sort((a: any, b: any) => (a.timestamp || 0) - (b.timestamp || 0));
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
            const ruleLabels = Array.from(new Set([deriveMatchedRuleLabel(event), deriveRuleLabelFromRuleObject(event?.decision?.matched_rule, step.outcome || eventOutcomeStatus(step)), event?.decision?.rule_name, event?.decision?.triggered_rule].filter(Boolean) as string[]));
            return (
              <div key={step.id} className="journeyTimeline__item">
                <button className={`journeyTimeline__card journeyTimeline__card--${statusTone(step.outcome || eventOutcomeStatus(step))}`} onClick={() => onOpenDecision(Number(step.id))}>
                  <div className="journeyTimeline__header"><span className="badge">Step {index + 1}</span><span className={`badge badge--${statusTone(step.outcome || eventOutcomeStatus(step))}`}>{step.outcome || eventOutcomeStatus(step)}</span></div>
                  <strong>{step.agent_name || 'agent'} {'->'} {step.tool || 'tool'}</strong>
                  <div className="muted">{fmtTs(step.timestamp)} · risk {Math.round(step.risk_score || 0)}</div>
                  <div className="muted">{displayValue(event?.decision?.route_target || step.route_target || step.domain || 'No route recorded')}</div>
                  <div className="muted">{(event?.action?.risk_score || 0) > 0 ? 'Primary scored step' : ((event?.decision?.matched_rule && !(event?.action?.risk_score || 0)) ? 'Follow-on inherited step' : 'Recorded trace step')}</div>
                </button>
                <div className="journeyTimeline__rules">
                  {ruleLabels.length ? ruleLabels.map((label) => <button key={label} className="badge badge--rule badge--clickable" onClick={() => onOpenRule(label, eventRuleBucket(step))}>{label}</button>) : <span className="muted">No explicit rule hit</span>}
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
          {trace.graph.edges.map((edge: any, idx: number) => {
            const source = byId.get(edge.source);
            const target = byId.get(edge.target);
            if (!source || !target) return null;
            return <line key={idx} x1={source.x + 72} y1={source.y} x2={target.x - 72} y2={target.y} className={`traceEdge traceEdge--${edge.kind || 'sequence'}`} />;
          })}
          {ruleNodes.map((rule: any) => {
            const source = byId.get(rule.parentId);
            if (!source) return null;
            return (
              <g key={rule.id}>
                <path d={`M ${source.x} ${source.y + 52} C ${source.x} ${source.y + 76}, ${rule.x} ${rule.y - 58}, ${rule.x} ${rule.y - 34}`} className={`traceEdge traceEdge--triggered traceEdge--${rule.severity}`} />
                <g transform={`translate(${rule.x}, ${rule.y})`} className="traceRuleNode" onClick={() => onOpenRule(String(rule.label), rule.severity === 'danger' ? 'block' : rule.severity === 'warn' ? 'warn' : rule.severity === 'monitor' ? 'monitor' : 'allow')}>
                  <rect x="-82" y="-26" width="164" height="52" rx="18" className={`traceRuleNode__card traceRuleNode__card--${rule.severity}`} />
                  <text x="0" y="-3" textAnchor="middle" className="traceRuleNode__title">{String(rule.label).slice(0, 26)}</text>
                  <text x="0" y="15" textAnchor="middle" className="traceRuleNode__meta">triggered rule</text>
                </g>
              </g>
            );
          })}
          {eventPositions.map((node: any) => {
            const event = eventMap.get(node.id);
            const matchedRule = event?.decision?.matched_rule;
            const matchedLabel = deriveMatchedRuleLabel(event) || deriveRuleLabelFromRuleObject(matchedRule, eventOutcomeStatus(event || node)) || '';
            return (
              <g key={node.id} transform={`translate(${node.x}, ${node.y})`} onClick={() => onOpenDecision(Number(node.id))} className="traceNode">
                <rect x="-72" y="-52" width="144" height="104" rx="24" className={`traceNode__card traceNode__card--${statusTone(eventOutcomeStatus(event || node))}`} />
                <text x="0" y="-14" textAnchor="middle" className="traceNode__title">{String(node.label || 'event').slice(0, 18)}</text>
                <text x="0" y="10" textAnchor="middle" className="traceNode__meta">{eventOutcomeStatus(event || node)}</text>
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
