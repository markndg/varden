import React from 'react';

type SankeyPanelProps = {
  overview: any;
  sourceEvents: any[];
  onFocus: (opts: { status?: string; search?: string; eventIds?: number[]; label?: string }) => void;
  mode?: 'agent_tool_outcome' | 'agent_rule_outcome' | 'tool_rule_outcome';
  helpers: {
    normalizeEventRow: (event: any) => any;
    eventOutcomeStatus: (event: any) => string;
    deriveMatchedRuleLabel: (event: any) => string | null;
  };
};

export function SankeyPanel({ sourceEvents, onFocus, mode = 'agent_tool_outcome', helpers }: SankeyPanelProps) {
  const { normalizeEventRow, eventOutcomeStatus, deriveMatchedRuleLabel } = helpers;
  const events = (sourceEvents || []).map(normalizeEventRow).filter((event) => event.id);
  const laneMaps: Record<string, Map<string, number>> = { left: new Map(), mid: new Map(), right: new Map() } as any;
  const flowCounts = new Map<string, { fromLane: 'left' | 'mid'; fromLabel: string; toLane: 'mid' | 'right'; toLabel: string; value: number; statuses: Record<string, number>; eventIds: number[] }>();
  const pushFlow = (fromLane: 'left' | 'mid', fromLabel: string, toLane: 'mid' | 'right', toLabel: string, status: string, eventId: number) => {
    const key = JSON.stringify([fromLane, fromLabel, toLane, toLabel]);
    const current = flowCounts.get(key) || { fromLane, fromLabel, toLane, toLabel, value: 0, statuses: {}, eventIds: [] };
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
    const outcome = event.outcome || eventOutcomeStatus(event);
    const ruleLabel = (event as any).matched_rule_label || deriveMatchedRuleLabel(event) || (outcome === 'allowed' ? 'no rule hit' : `${outcome} decision`);
    const mid = mode === 'agent_tool_outcome' ? (event.tool || 'unknown tool') : ruleLabel;
    const status = outcome;
    const right = ruleLabel && mode !== 'agent_tool_outcome' ? `${status} · ${ruleLabel}` : status;
    laneMaps.left.set(left, (laneMaps.left.get(left) || 0) + 1);
    laneMaps.mid.set(mid, (laneMaps.mid.get(mid) || 0) + 1);
    laneMaps.right.set(right, (laneMaps.right.get(right) || 0) + 1);
    pushFlow('left', left, 'mid', mid, status, event.id);
    pushFlow('mid', mid, 'right', right, status, event.id);
  }
  const leftNodesRaw = Array.from(laneMaps.left.entries()).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const midNodesRaw = Array.from(laneMaps.mid.entries()).sort((a, b) => b[1] - a[1]).slice(0, 10);
  const rightNodesRaw = Array.from(laneMaps.right.entries()).sort((a, b) => b[1] - a[1]).slice(0, 8);
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
    const blocked = statuses.blocked || 0;
    const warned = statuses.warned || 0;
    const monitor = statuses.monitor || 0;
    if (blocked > 0 && blocked >= warned && blocked >= monitor) return 'danger';
    if (warned > 0 && warned >= monitor) return 'warn';
    if (monitor > 0) return 'monitor';
    return 'ok';
  };
  const edges: Array<{ source: any; target: any; value: number; tone: string; eventIds: number[] }> = [];
  for (const entry of flowCounts.values()) {
    const from = nodeByKey.get(`${entry.fromLane}:${entry.fromLabel}`);
    const to = nodeByKey.get(`${entry.toLane}:${entry.toLabel}`);
    if (from && to) edges.push({ source: from, target: to, value: entry.value, tone: dominantTone(entry.statuses), eventIds: entry.eventIds });
  }
  const height = Math.max(260, Math.max(leftNodes.length, midNodes.length, rightNodes.length) * (laneHeight + gap) + 40);
  const outcomeTone = (label: string) => label.startsWith('blocked') ? 'danger' : label.startsWith('warned') ? 'warn' : label.startsWith('monitor') ? 'monitor' : 'ok';
  return (
    <div className="sankeyWrap">
      <div className="traceSummaryBar"><span>{leftLabel} → {midLabel} → {rightLabel}</span><span>{events.length} observed actions</span><span>Top nodes per column by volume; other flows are not drawn. Click nodes or lanes to filter.</span></div>
      <div className="signalLegend"><span><i className="legendSwatch legendSwatch--danger" />Blocked-heavy path</span><span><i className="legendSwatch legendSwatch--warn" />Warn-heavy path</span><span><i className="legendSwatch legendSwatch--monitor" />Monitor-heavy path</span><span><i className="legendSwatch legendSwatch--ok" />Allow-heavy path</span></div>
      <div className="sankeyScroller">
        <svg width="980" height={height} viewBox={`0 0 980 ${height}`} className="traceSvg">
          <text x="100" y="20" className="traceNode__meta">{leftLabel}</text><text x="420" y="20" className="traceNode__meta">{midLabel}</text><text x="740" y="20" className="traceNode__meta">{rightLabel}</text>
          {edges.map((edge, idx) => {
            const x1 = edge.source.x + nodeWidth; const y1 = edge.source.y + laneHeight / 2; const x2 = edge.target.x; const y2 = edge.target.y + laneHeight / 2; const dx = (x2 - x1) * 0.5;
            return <path key={idx} d={`M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`} className={`sankeyEdge sankeyEdge--${edge.tone}`} style={{ strokeWidth: 8 + (edge.value / maxFlow) * 16 }} onClick={() => onFocus({ eventIds: edge.eventIds, label: `${edge.value} events on ${edge.tone} path` })} />;
          })}
          {[...leftNodes, ...midNodes, ...rightNodes].map((node) => (
            <g
              key={`${node.lane}-${node.key}`}
              className="sankeyNode"
              transform={`translate(${node.x}, ${node.y})`}
              onClick={() => {
                if (node.lane === 'left') onFocus({ search: node.key, eventIds: events.filter((event) => (mode === 'tool_rule_outcome' ? event.tool : event.agent_name) === node.key).map((event) => event.id), label: `${leftLabel} focus · ${node.key}` });
                if (node.lane === 'mid') onFocus({ search: node.key, eventIds: events.filter((event) => { const outcome = event.outcome || eventOutcomeStatus(event); return (mode === 'agent_tool_outcome' ? event.tool : (((event as any).matched_rule_label || deriveMatchedRuleLabel(event) || (outcome === 'allowed' ? 'no rule hit' : `${outcome} decision`)))) === node.key; }).map((event) => event.id), label: `${midLabel} focus · ${node.key}` });
                if (node.lane === 'right') {
                  const status = node.key.startsWith('blocked') ? 'blocked' : node.key.startsWith('warned') ? 'warned' : node.key.startsWith('monitor') ? 'monitor' : 'allowed';
                  onFocus({ status, eventIds: events.filter((event) => (event.outcome || eventOutcomeStatus(event)) === status).map((event) => event.id), label: `Outcome focus · ${node.key}` });
                }
              }}
            >
              <rect width={nodeWidth} height={laneHeight} rx="18" className={`sankeyNode__card sankeyNode__card--${node.lane === 'right' ? outcomeTone(node.key) : 'neutral'}`} />
              <text x="16" y="24" className="sankeyNode__title">{String(node.key).slice(0, 28)}</text>
              <text x="16" y="42" className="sankeyNode__meta">{node.value} events</text>
            </g>
          ))}
        </svg>
      </div>
    </div>
  );
}
