/**
 * Predictive Authority page — visual security explanation.
 * Renders authoritative backend graph/view models only.
 * Never invents nodes, edges, hazards, or confidence.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  CapabilityGroup,
  DisplayLabel,
  GraphEdge,
  GraphMode,
  GraphNode,
  buildCapabilityGroups,
  columnFor,
  columnIndex,
  computeStableLayout,
  decisionRank,
  edst,
  eid,
  esrc,
  filterNodesForMode,
  formatDecision,
  humanizeLabel,
  isEdgeOnPath,
  isPotentialNode,
  nid,
  nodeState,
  opacityForEmphasis,
  orthogonalPath,
  pickPrimaryTrajectory,
} from '../../lib/predictiveGraphLayout';

type Helpers = {
  api: (path: string, init?: any, token?: string) => Promise<any>;
  classNames: (...parts: any[]) => string;
  token?: string;
};

type InspectorFocus = 'trajectory' | 'node' | 'edge' | 'gate' | 'empty';

const GRAPH_W = 980;
const GRAPH_H = 460;
const NODE_W = 148;
const NODE_H = 56;

function Icon({ name }: { name: string }) {
  const common = { width: 12, height: 12, viewBox: '0 0 16 16', 'aria-hidden': true as const };
  switch (name) {
    case 'message':
      return (
        <svg {...common}>
          <path fill="currentColor" d="M2 3h12v8H8l-3 2v-2H2V3zm2 2v1h8V5H4zm0 3v1h5V8H4z" />
        </svg>
      );
    case 'file':
      return (
        <svg {...common}>
          <path fill="currentColor" d="M4 1h6l3 3v11H4V1zm6 1.5V5h2.5L10 2.5zM6 8h5v1H6V8zm0 2h5v1H6v-1zm0 2h4v1H6v-1z" />
        </svg>
      );
    case 'key':
      return (
        <svg {...common}>
          <path fill="currentColor" d="M8 2a4 4 0 00-1.5 7.7V14h2v-1h2v-2H9.5V9.7A4 4 0 008 2zm0 2a2 2 0 110 4 2 2 0 010-4z" />
        </svg>
      );
    case 'cloud':
      return (
        <svg {...common}>
          <path fill="currentColor" d="M6 5a3 3 0 015.8.8A2.5 2.5 0 0113 11H5.5A2.5 2.5 0 015 6.1 3 3 0 016 5z" />
        </svg>
      );
    case 'globe':
      return (
        <svg {...common}>
          <path fill="currentColor" d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 1.5c1.2 0 2.3 2.3 2.5 5H5.5c.2-2.7 1.3-5 2.5-5zm-2.5 6.5h5c-.2 2.7-1.3 5-2.5 5s-2.3-2.3-2.5-5zM3.2 8c.3-1.5.9-2.9 1.7-3.8A5.5 5.5 0 003.2 8zm8 0a5.5 5.5 0 01-1.7 3.8c.8-.9 1.4-2.3 1.7-3.8z" />
        </svg>
      );
    case 'filter':
      return (
        <svg {...common}>
          <path fill="currentColor" d="M2 3h12l-4 5v4l-4 2V8L2 3z" />
        </svg>
      );
    default:
      return (
        <svg {...common}>
          <circle cx="8" cy="8" r="5" fill="none" stroke="currentColor" strokeWidth="1.5" />
        </svg>
      );
  }
}

function NodeCard({
  n,
  label,
  emphasis,
  onPath,
  selected,
  onSelect,
  classNames,
}: {
  n: GraphNode;
  label: DisplayLabel;
  emphasis: string;
  onPath: boolean;
  selected: boolean;
  onSelect: () => void;
  classNames: Helpers['classNames'];
}) {
  const potential = isPotentialNode(n);
  return (
    <g
      transform={`translate(${0},${0})`}
      opacity={1}
      onClick={(e) => {
        e.stopPropagation();
        onSelect();
      }}
      style={{ cursor: 'pointer' }}
      data-testid={`pa-node-${nid(n)}`}
      data-emphasis={emphasis}
      data-predicted={potential ? 'true' : 'false'}
      data-on-path={onPath ? 'true' : 'false'}
    >
      <title>{`${label.title}\n${String(n.label || nid(n))}\n${label.state}`}</title>
      <rect
        x={-NODE_W / 2}
        y={-NODE_H / 2}
        width={NODE_W}
        height={NODE_H}
        rx={10}
        className={classNames(
          'paNode',
          `paNode--${nodeState(n)}`,
          onPath && 'paNode--hazard',
          selected && 'paNode--selected',
          potential && 'paNode--predicted',
        )}
        strokeDasharray={potential ? '4 3' : undefined}
      />
      <foreignObject x={-NODE_W / 2 + 6} y={-NODE_H / 2 + 6} width={NODE_W - 12} height={NODE_H - 12}>
        <div className={classNames('paNodeInner', potential && 'is-potential', onPath && 'is-path')}>
          <div className="paNodeInner__top">
            <span className="paNodeInner__icon">
              <Icon name={label.icon} />
            </span>
            <span className="paNodeInner__state">{label.state}</span>
          </div>
          <div className="paNodeInner__title">{label.title}</div>
          <div className="paNodeInner__sub">{label.subtitle}</div>
        </div>
      </foreignObject>
    </g>
  );
}

export function PredictiveAuthorityPage({
  helpers,
  onOpenDecision,
  initialEventId = null,
  onClearHistorical,
}: {
  helpers: Helpers;
  onOpenDecision?: (id: number) => void;
  initialEventId?: number | null;
  onClearHistorical?: () => void;
}) {
  const { api, classNames, token } = helpers;
  const [session, setSession] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [traceId, setTraceId] = useState('ui-demo');
  const [tenantId, setTenantId] = useState('demo');
  const [mode, setMode] = useState<GraphMode>('trajectory');
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);
  const [gateSelected, setGateSelected] = useState(false);
  const [selectedPath, setSelectedPath] = useState<any | null>(null);
  const [eventIndex, setEventIndex] = useState<number>(-1);
  const [eventDetail, setEventDetail] = useState<any | null>(null);
  const [historicalEventId, setHistoricalEventId] = useState<number | null>(initialEventId);
  const [showPotential, setShowPotential] = useState(true);
  const [showContext, setShowContext] = useState(true);
  const [inspectorOpen, setInspectorOpen] = useState(true);
  const [groupsCollapsed, setGroupsCollapsed] = useState<Record<string, boolean>>({});
  const [matrixOpen, setMatrixOpen] = useState(true);
  const [fitTick, setFitTick] = useState(0);

  useEffect(() => {
    setHistoricalEventId(initialEventId);
  }, [initialEventId]);

  const applyStoryDefaults = useCallback((detail: any) => {
    const trajs = (detail?.hazardous_paths || []).map((p: any, i: number) =>
      typeof p === 'string' ? { pattern: 'path', path: { display: p, nodes: [] }, description: p, index: i } : { ...p, index: i },
    );
    const primary = pickPrimaryTrajectory(trajs);
    setSelectedPath(primary);
    setSelectedNode(null);
    setSelectedEdge(null);
    setGateSelected(Boolean(primary));
    setMode(primary ? 'trajectory' : 'after');
    setInspectorOpen(true);
  }, []);

  const loadHistorical = useCallback(
    async (eventId: number) => {
      setLoading(true);
      setError(null);
      try {
        const detail = await api(`/predictive/from-event/${eventId}`, undefined, token);
        if (detail?.availability && detail.availability !== 'ok') {
          setEventDetail(null);
          setSession({ live: false, historical: true, events: [], analysis_status: 'unavailable' });
          setError(String(detail.message || detail.error || 'Predictive analysis is not available for this event.'));
          return;
        }
        if (detail?.trusted === false && detail?.integrity && detail.integrity !== 'ok') {
          setEventDetail(null);
          setSession({ live: false, historical: true, events: [], analysis_status: 'integrity_failed' });
          setError(String(detail.message || 'Predictive snapshot integrity verification failed.'));
          return;
        }
        setEventDetail(detail);
        setSession({
          live: false,
          historical: true,
          analysis_status: detail.analysis_status,
          analysis_incomplete_reason: detail.analysis_incomplete_reason,
          events: [{ ...detail, event_id: eventId }],
          graph: detail.graph,
          last_explanation: detail.explanation,
        });
        setEventIndex(0);
        if (detail.trace_id) setTraceId(String(detail.trace_id));
        if (detail.tenant_id) setTenantId(String(detail.tenant_id));
        applyStoryDefaults(detail);
      } catch (e: any) {
        setEventDetail(null);
        setError(String(e?.message || e || 'failed to load historical event'));
      } finally {
        setLoading(false);
      }
    },
    [api, token, applyStoryDefaults],
  );

  const load = useCallback(async () => {
    if (historicalEventId) {
      await loadHistorical(historicalEventId);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const data = await api(`/predictive/status?trace_id=${encodeURIComponent(traceId)}&tenant_id=${encodeURIComponent(tenantId)}`, undefined, token);
      setSession(data);
      const events = data?.events || [];
      if (events.length) {
        const idx = eventIndex < 0 ? events.length - 1 : Math.min(eventIndex, events.length - 1);
        setEventIndex(idx);
        const detail = await api(
          `/predictive/session/events/${idx}?trace_id=${encodeURIComponent(traceId)}&tenant_id=${encodeURIComponent(tenantId)}`,
          undefined,
          token,
        );
        setEventDetail(detail);
        if (!selectedPath) applyStoryDefaults(detail);
      } else {
        setEventDetail(null);
      }
    } catch (e: any) {
      setError(String(e?.message || e || 'failed to load'));
    } finally {
      setLoading(false);
    }
  }, [api, token, traceId, tenantId, eventIndex, historicalEventId, loadHistorical, applyStoryDefaults, selectedPath]);

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [historicalEventId, traceId, tenantId, eventIndex]);

  const returnToLive = () => {
    setHistoricalEventId(null);
    setEventDetail(null);
    setError(null);
    onClearHistorical?.();
  };

  const runDemo = async () => {
    setLoading(true);
    try {
      setHistoricalEventId(null);
      onClearHistorical?.();
      const fixture = await api('/predictive/demo?mode=enforce', { method: 'POST' }, token);
      setTenantId('demo');
      setTraceId('ui-demo');
      setSession(fixture.hazardous);
      const events = fixture.hazardous?.events || [];
      setEventIndex(events.length - 1);
      const detail = events[events.length - 1] || fixture.hazardous;
      setEventDetail(detail);
      applyStoryDefaults(detail);
      setFitTick((t) => t + 1);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setLoading(false);
    }
  };

  const isHistorical = Boolean(historicalEventId || eventDetail?.historical || eventDetail?.view_kind === 'historical');

  const fullGraph = useMemo(() => {
    const g = eventDetail?.graph || session?.graph || { nodes: [], edges: [] };
    return {
      nodes: (g.nodes || []) as GraphNode[],
      edges: (g.edges || []) as GraphEdge[],
      truncated: g.truncated,
      truncation_reason: g.truncation_reason,
    };
  }, [session, eventDetail]);

  const trajectories = useMemo(
    () =>
      (eventDetail?.hazardous_paths || session?.last_explanation?.hazardous_paths || []).map((p: any, i: number) =>
        typeof p === 'string' ? { pattern: 'path', path: { display: p, nodes: [] }, description: p, index: i } : { ...p, index: i },
      ),
    [eventDetail, session],
  );

  const pathNodeSet = useMemo(() => new Set<string>(selectedPath?.path?.nodes || []), [selectedPath]);

  const groups: CapabilityGroup[] = useMemo(() => buildCapabilityGroups(fullGraph.nodes), [fullGraph.nodes]);

  // Collapse large AWS fans in trajectory when the path does not need them; expand in Predicted.
  useEffect(() => {
    if (!groups.length) return;
    setGroupsCollapsed((prev) => {
      const next = { ...prev };
      for (const g of groups) {
        const pathHits = g.memberIds.some((id) => pathNodeSet.has(id));
        if (mode === 'after' || mode === 'delta') next[g.id] = false;
        else if (mode === 'trajectory') next[g.id] = !pathHits;
        else if (mode === 'before') next[g.id] = true;
        else if (next[g.id] === undefined) next[g.id] = true;
      }
      return next;
    });
  }, [groups, mode, pathNodeSet]);

  const modeFilter = useMemo(
    () =>
      filterNodesForMode(fullGraph.nodes, mode, {
        before: eventDetail?.before,
        after: eventDetail?.after,
        pathNodes: pathNodeSet,
        showPotential,
        showContext,
      }),
    [fullGraph.nodes, mode, eventDetail, pathNodeSet, showPotential, showContext],
  );

  const layout = useMemo(
    () => computeStableLayout(fullGraph.nodes, GRAPH_W, GRAPH_H, { groups, groupsCollapsed }),
    [fullGraph.nodes, groups, groupsCollapsed, fitTick],
  );

  const enforcement = eventDetail
    ? {
        existing: eventDetail.existing_decision,
        recommendation: eventDetail.recommendation || eventDetail.predictive_recommendation,
        final: eventDetail.final_decision,
        mode: eventDetail.mode,
        status: eventDetail.analysis_status,
        incomplete: eventDetail.analysis_incomplete_reason,
      }
    : null;

  const showGate = Boolean(enforcement && decisionRank(enforcement.final) >= decisionRank('require_approval'));
  const delta = eventDetail?.delta || null;
  const explanation = eventDetail?.explanation || session?.last_explanation || null;

  const inspectorFocus: InspectorFocus = gateSelected
    ? 'gate'
    : selectedEdge
      ? 'edge'
      : selectedNode
        ? 'node'
        : selectedPath
          ? 'trajectory'
          : 'empty';

  const awsMatrix = useMemo(() => {
    const aws = fullGraph.nodes.filter((n) => /aws\./i.test(String(n.label || '')));
    const services = ['s3', 'iam', 'ec2'] as const;
    const ops = [
      { key: 'read', label: 'READ' },
      { key: 'write|modify', label: 'WRITE/MODIFY' },
    ];
    return { aws, services, ops };
  }, [fullGraph.nodes]);

  const selectPath = (t: any) => {
    setSelectedPath(t);
    setSelectedNode(null);
    setSelectedEdge(null);
    setGateSelected(true);
    setMode('trajectory');
    // Expand groups that intersect path
    const nodes = new Set<string>(t?.path?.nodes || []);
    setGroupsCollapsed((prev) => {
      const next = { ...prev };
      for (const g of groups) {
        if (g.memberIds.some((id) => nodes.has(id))) next[g.id] = false;
      }
      return next;
    });
  };

  const regionLabels = (
    <g className="paRegions" pointerEvents="none">
      <text x={70} y={22} className="paRegionLabel">
        OBSERVED
      </text>
      <text x={GRAPH_W * 0.52} y={22} className="paRegionLabel paRegionLabel--pred">
        PREDICTED / REACHABLE
      </text>
      {showGate ? (
        <text x={GRAPH_W - 120} y={22} className="paRegionLabel paRegionLabel--gate">
          INTERRUPT
        </text>
      ) : null}
      <line x1={GRAPH_W * 0.42} y1={30} x2={GRAPH_W * 0.42} y2={GRAPH_H - 20} className="paRegionRule" />
    </g>
  );

  return (
    <div className="paPage" data-testid="predictive-page" data-view-kind={isHistorical ? 'historical' : 'live'} data-mode={mode}>
      <div className="paPage__header">
        <div>
          <div className="eyebrow">Predictive Authority</div>
          <h2>{isHistorical ? 'Historical Event' : 'What this action makes reachable'}</h2>
          <p className="muted">
            {isHistorical
              ? 'Immutable security state as Varden knew it when this decision was recorded — not live authority.'
              : 'Reachable authority if this transition is permitted — not a forecast of what the agent will choose next.'}
          </p>
          <details className="paAbout" data-testid="pa-about">
            <summary>About Predictive Authority</summary>
            <p>
              Varden does not predict what the agent will choose to do. It deterministically computes what
              authority becomes reachable under the current evidence-backed security model if this action is
              allowed. <strong>OBSERVED</strong> means already executed; <strong>CONFIRMED</strong> means
              evidence-backed authority; <strong>POTENTIAL</strong> means reachable but not confirmed as
              exercised; <strong>PREDICTED</strong> is the state after evaluating the proposed transition;
              <strong> COUNTERFACTUAL</strong> is what would become reachable if an interrupted action were
              permitted.
            </p>
          </details>
        </div>
        <div className="paPage__actions">
          {isHistorical ? (
            <button type="button" className="button button--ghost" onClick={returnToLive} data-testid="return-to-live">
              Return to Live
            </button>
          ) : null}
          <button type="button" className="button" onClick={() => load()} disabled={loading}>
            Refresh
          </button>
          <button type="button" className="button button--accent" onClick={runDemo} disabled={loading} data-testid="load-demo">
            Load demo
          </button>
        </div>
      </div>

      {error ? (
        <div className="banner banner--warn" data-testid="predictive-error">
          {error}
        </div>
      ) : null}

      <div className="paMetrics" data-testid="pa-metrics">
        <div className={classNames('paMetric', isHistorical ? 'is-historical' : 'is-live')} data-testid="view-kind-pill">
          <span className="paMetric__k">{isHistorical ? 'HISTORICAL' : 'LIVE'}</span>
          <strong>{String(session?.analysis_status || 'off').toUpperCase()}</strong>
        </div>
        <div className="paMetric">
          <span className="paMetric__k">Existing</span>
          <strong>{String(enforcement?.existing || '—').replace(/_/g, ' ').toUpperCase()}</strong>
        </div>
        <div className="paMetric paMetric--pred">
          <span className="paMetric__k">Predictive</span>
          <strong data-testid="predictive-recommendation">{formatDecision(enforcement?.recommendation, enforcement?.mode)}</strong>
        </div>
        <div className="paMetric paMetric--final">
          <span className="paMetric__k">Final</span>
          <strong data-testid="final-decision">{formatDecision(enforcement?.final, enforcement?.mode === 'observe' ? undefined : enforcement?.mode)}</strong>
        </div>
        <div className="paMetric">
          <span className="paMetric__k">New authority</span>
          <strong>
            +
            {(() => {
              const listed = (delta?.added_capabilities || []).length;
              const pot =
                delta?.potential_added_count ??
                (delta?.added_capabilities || []).filter((c: any) => c.kind === 'potential').length;
              const graphPot = fullGraph.nodes.filter((n) => isPotentialNode(n)).length;
              return Math.max(Number(pot) || 0, Number(listed) || 0, graphPot || 0);
            })()}
          </strong>
        </div>
        <div className="paMetric">
          <span className="paMetric__k">Hazardous paths</span>
          <strong>{trajectories.length}</strong>
        </div>
      </div>

      <div className="paToolbar paToolbar--compact">
        {(['before', 'after', 'delta', 'trajectory'] as GraphMode[]).map((m) => (
          <button
            key={m}
            type="button"
            className={classNames('paTab', mode === m && 'is-active')}
            data-testid={`mode-${m}`}
            onClick={() => setMode(m)}
          >
            {m === 'before' ? 'Before' : m === 'after' ? 'Predicted' : m === 'delta' ? 'Delta' : 'Trajectory'}
          </button>
        ))}
        <label className="paCheck">
          Path
          <select
            className="input input--small"
            value={selectedPath ? String(selectedPath.index ?? trajectories.indexOf(selectedPath)) : ''}
            onChange={(e) => {
              const t = trajectories[Number(e.target.value)];
              if (t) selectPath(t);
            }}
            aria-label="Primary path"
          >
            <option value="">None</option>
            {trajectories.map((t: any, i: number) => (
              <option key={i} value={i}>
                {i + 1}. {(t.pattern || 'path').replace(/_/g, ' ')}
              </option>
            ))}
          </select>
        </label>
        <label className="paCheck">
          <input type="checkbox" checked={showPotential} onChange={(e) => setShowPotential(e.target.checked)} /> Potential
        </label>
        <label className="paCheck">
          <input type="checkbox" checked={showContext} onChange={(e) => setShowContext(e.target.checked)} /> Context
        </label>
        <button type="button" className="button button--ghost" onClick={() => setFitTick((t) => t + 1)}>
          Fit
        </button>
        <button type="button" className="button button--ghost" onClick={() => setInspectorOpen((v) => !v)} data-testid="toggle-inspector">
          {inspectorOpen ? 'Hide inspector' : 'Show inspector'}
        </button>
      </div>

      <div className={classNames('paLayout', !inspectorOpen && 'paLayout--wide')}>
        <div className="paGraphPanel" data-testid="graph-panel">
          <div className="paCanvasMeta">
            <span data-testid="observed-predicted-banner">
              {mode === 'before'
                ? 'OBSERVED — predicted expansion hidden'
                : mode === 'after'
                  ? 'PREDICTED — reachable if allowed (not executed)'
                  : mode === 'delta'
                    ? 'DELTA — structural authority expansion'
                    : 'TRAJECTORY — primary hazardous path + interrupt'}
            </span>
            {mode === 'before' && (delta?.potential_added_count || 0) > 0 ? (
              <span className="muted">Predicted expansion hidden · +{delta.potential_added_count} potential</span>
            ) : null}
          </div>
          <svg className="paGraph" viewBox={`0 0 ${GRAPH_W} ${GRAPH_H}`} role="img" aria-label="Authority graph" data-testid="predictive-graph">
            <defs>
              <marker id="paArrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                <path d="M0,0 L6,3 L0,6 Z" className="paArrowHead" />
              </marker>
              <marker id="paArrowHazard" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                <path d="M0,0 L6,3 L0,6 Z" className="paArrowHead paArrowHead--hazard" />
              </marker>
            </defs>
            {mode !== 'before' ? regionLabels : (
              <text x={70} y={22} className="paRegionLabel">
                OBSERVED / CURRENT
              </text>
            )}

            {/* Capability group frames */}
            {groups.map((g) => {
              if (groupsCollapsed[g.id]) {
                const p = layout[g.id];
                if (!p || mode === 'before') return null;
                return (
                  <g
                    key={g.id}
                    transform={`translate(${p.x},${p.y})`}
                    className="paGroupCollapsed"
                    data-testid={`capability-group-${g.id}`}
                    onClick={() => setGroupsCollapsed((prev) => ({ ...prev, [g.id]: false }))}
                    style={{ cursor: 'pointer' }}
                  >
                    <rect x={-70} y={-28} width={140} height={56} rx={12} className="paGroupBox" />
                    <text textAnchor="middle" y={-4} className="paNodeLabel">
                      {g.title}
                    </text>
                    <text textAnchor="middle" y={14} className="paNodeKind">
                      {g.potentialCount} potential · expand
                    </text>
                  </g>
                );
              }
              const members = g.memberIds.map((id) => layout[id]).filter(Boolean);
              if (!members.length || mode === 'before') return null;
              const xs = members.map((p) => p.x);
              const ys = members.map((p) => p.y);
              const minX = Math.min(...xs) - 72;
              const maxX = Math.max(...xs) + 72;
              const minY = Math.min(...ys) - 36;
              const maxY = Math.max(...ys) + 36;
              return (
                <g key={g.id} data-testid={`capability-group-${g.id}`}>
                  <rect x={minX} y={minY} width={maxX - minX} height={maxY - minY} rx={14} className="paGroupFrame" />
                  <text x={minX + 10} y={minY + 16} className="paGroupTitle">
                    {g.title}
                  </text>
                  <text
                    x={maxX - 8}
                    y={minY + 16}
                    textAnchor="end"
                    className="paGroupTitle"
                    style={{ cursor: 'pointer' }}
                    onClick={() => setGroupsCollapsed((prev) => ({ ...prev, [g.id]: true }))}
                  >
                    collapse
                  </text>
                </g>
              );
            })}

            {/* Edges */}
            {fullGraph.edges.map((e) => {
              const s = esrc(e);
              const d = edst(e);
              if (!modeFilter.visible.has(s) || !modeFilter.visible.has(d)) return null;
              const sNode = fullGraph.nodes.find((n) => nid(n) === s);
              const dNode = fullGraph.nodes.find((n) => nid(n) === d);
              if (sNode && dNode) {
                const jump = Math.abs(columnIndex(columnFor(sNode)) - columnIndex(columnFor(dNode)));
                // Calm before-mode: skip long-range chords that create hairballs.
                if (mode === 'before' && jump > 1) return null;
              }
              // Skip edges into collapsed group members (draw to group instead optionally later)
              const sGroup = groups.find((g) => groupsCollapsed[g.id] && g.memberIds.includes(s));
              const dGroup = groups.find((g) => groupsCollapsed[g.id] && g.memberIds.includes(d));
              const a = layout[sGroup ? sGroup.id : s];
              const b = layout[dGroup ? dGroup.id : d];
              if (!a || !b) return null;
              if (sGroup && dGroup && sGroup.id === dGroup.id) return null;
              const onPath = mode !== 'before' && selectedPath ? isEdgeOnPath(e, pathNodeSet) : false;
              const pot = e.state === 'potential' || e.evidenceKind === 'potential' || e.evidenceKind === 'untrusted_declared';
              const emph = onPath ? 'primary' : modeFilter.emphasis[s] === 'context' || modeFilter.emphasis[d] === 'context' ? 'context' : pot ? 'alt' : 'primary';
              const op = opacityForEmphasis(onPath ? 'primary' : emph, mode);
              if (op <= 0) return null;
              return (
                <path
                  key={eid(e)}
                  d={orthogonalPath(a, b)}
                  className={classNames('paEdge', pot && 'paEdge--potential', onPath && 'paEdge--hazard')}
                  markerEnd={onPath ? 'url(#paArrowHazard)' : 'url(#paArrow)'}
                  opacity={op}
                  data-testid={onPath ? 'path-edge' : undefined}
                  onClick={(ev) => {
                    ev.stopPropagation();
                    setSelectedEdge(e);
                    setSelectedNode(null);
                    setGateSelected(false);
                  }}
                />
              );
            })}

            {/* Path step numbers */}
            {mode === 'trajectory' && selectedPath?.path?.nodes
              ? (selectedPath.path.nodes as string[]).map((id: string, i: number) => {
                  const p = layout[id];
                  if (!p || !modeFilter.visible.has(id)) return null;
                  return (
                    <g key={`step-${id}`} transform={`translate(${p.x - NODE_W / 2 - 8},${p.y - NODE_H / 2 - 8})`}>
                      <circle r={10} className="paStepBadge" cx={0} cy={0} />
                      <text textAnchor="middle" y={4} className="paStepBadgeText">
                        {i + 1}
                      </text>
                    </g>
                  );
                })
              : null}

            {/* Nodes */}
            {fullGraph.nodes.map((n) => {
              const id = nid(n);
              if (!modeFilter.visible.has(id)) return null;
              if (groups.some((g) => groupsCollapsed[g.id] && g.memberIds.includes(id))) return null;
              const p = layout[id];
              if (!p) return null;
              const emph = modeFilter.emphasis[id] || 'primary';
              const op = opacityForEmphasis(emph, mode);
              if (op <= 0) return null;
              const onPath = mode !== 'before' && pathNodeSet.has(id);
              const label = humanizeLabel(n);
              return (
                <g key={id} transform={`translate(${p.x},${p.y})`} opacity={op}>
                  <NodeCard
                    n={n}
                    label={label}
                    emphasis={emph}
                    onPath={onPath}
                    selected={selectedNode != null && nid(selectedNode) === id}
                    classNames={classNames}
                    onSelect={() => {
                      setSelectedNode(n);
                      setSelectedEdge(null);
                      setGateSelected(false);
                    }}
                  />
                </g>
              );
            })}

            {/* Presentation-only link from path tip to gate (not a backend edge). */}
            {showGate && mode !== 'before' && selectedPath?.path?.nodes?.length
              ? (() => {
                  const lastId = selectedPath.path.nodes[selectedPath.path.nodes.length - 1];
                  const a = layout[lastId];
                  const b = layout.__gate__;
                  if (!a || !b || !modeFilter.visible.has(lastId)) return null;
                  return (
                    <path
                      key="gate-link"
                      d={orthogonalPath(a, b)}
                      className="paEdge paEdge--hazard paEdge--gateLink"
                      markerEnd="url(#paArrowHazard)"
                      data-testid="gate-link"
                      opacity={1}
                    />
                  );
                })()
              : null}

            {showGate && mode !== 'before' ? (
              <g
                transform={`translate(${layout.__gate__?.x || GRAPH_W - 70},${layout.__gate__?.y || GRAPH_H / 2})`}
                data-testid="enforcement-point"
                data-gate="true"
                onClick={() => {
                  setGateSelected(true);
                  setSelectedNode(null);
                  setSelectedEdge(null);
                }}
                style={{ cursor: 'pointer' }}
              >
                <rect x={-78} y={-48} width={156} height={96} rx={4} className="paGate" />
                <text textAnchor="middle" y={-18} className="paGateEyebrow">
                  VARDEN SECURITY GATE
                </text>
                <text textAnchor="middle" y={6} className="paGateDecision">
                  {formatDecision(enforcement?.final, enforcement?.mode)}
                </text>
                <text textAnchor="middle" y={28} className="paGateStop">
                  progression stops here
                </text>
                <text textAnchor="middle" y={44} className="paGateX">
                  ╳
                </text>
              </g>
            ) : null}
          </svg>

          {matrixOpen && awsMatrix.aws.length >= 3 && mode !== 'before' ? (
            <div className="paMatrix" data-testid="capability-matrix">
              <div className="paMatrix__head">
                <strong>AWS authority</strong>
                <button type="button" className="button button--ghost" onClick={() => setMatrixOpen(false)}>
                  Hide
                </button>
              </div>
              <table>
                <thead>
                  <tr>
                    <th />
                    {awsMatrix.ops.map((o) => (
                      <th key={o.key}>{o.label}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {awsMatrix.services.map((svc) => (
                    <tr key={svc}>
                      <th>{svc.toUpperCase()}</th>
                      {awsMatrix.ops.map((o) => {
                        const hit = awsMatrix.aws.find((n) => {
                          const lab = String(n.label || '');
                          return lab.includes(`aws.${svc}.`) && new RegExp(o.key, 'i').test(lab);
                        });
                        const pot = hit ? isPotentialNode(hit) : false;
                        return (
                          <td key={o.key}>
                            {hit ? (
                              <button
                                type="button"
                                className={classNames('paMatrixDot', pot ? 'is-potential' : 'is-confirmed')}
                                title={String(hit.label)}
                                onClick={() => {
                                  setSelectedNode(hit);
                                  setGateSelected(false);
                                  setGroupsCollapsed((prev) => {
                                    const next = { ...prev };
                                    for (const g of groups) if (g.memberIds.includes(nid(hit))) next[g.id] = false;
                                    return next;
                                  });
                                }}
                              >
                                {pot ? '◌' : '●'}
                              </button>
                            ) : (
                              <span className="muted">·</span>
                            )}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="muted">● confirmed · ◌ potential — clicks select real graph nodes</div>
            </div>
          ) : null}
        </div>

        {inspectorOpen ? (
          <aside className="paInspector" data-testid="evidence-inspector" data-focus={inspectorFocus}>
            <div className="eyebrow">Evidence</div>
            {inspectorFocus === 'trajectory' && selectedPath && mode !== 'before' ? (
              <div data-testid="inspector-trajectory">
                <h3>Trajectory</h3>
                <p>{(selectedPath.pattern || 'hazardous path').replace(/_/g, ' ')}</p>
                <p className="paTrajPath">{selectedPath.path?.display || selectedPath.description}</p>
                <dl className="paDl">
                  <dt>Decision</dt>
                  <dd>{formatDecision(enforcement?.final, enforcement?.mode)}</dd>
                  <dt>Why</dt>
                  <dd>{explanation?.reason || selectedPath.description || 'Hazardous authority expansion is reachable.'}</dd>
                  <dt>Steps</dt>
                  <dd>{(selectedPath.path?.nodes || []).length || '—'}</dd>
                </dl>
                <button type="button" className="button" onClick={() => setGateSelected(true)}>
                  Open enforcement explanation
                </button>
              </div>
            ) : null}
            {inspectorFocus === 'gate' && enforcement && mode !== 'before' ? (
              <div data-testid="inspector-gate">
                <h3>Varden interrupt</h3>
                <dl className="paDl">
                  <dt>Decision</dt>
                  <dd>{formatDecision(enforcement.final, enforcement.mode)}</dd>
                  <dt>Existing policy</dt>
                  <dd>{String(enforcement.existing || '').toUpperCase()}</dd>
                  <dt>Predictive recommendation</dt>
                  <dd>{formatDecision(enforcement.recommendation, enforcement.mode)}</dd>
                  <dt>Final decision</dt>
                  <dd>{String(enforcement.final || '').replace(/_/g, ' ').toUpperCase()}</dd>
                  <dt>Reason</dt>
                  <dd>{explanation?.reason || eventDetail?.recommendation?.reason || 'Authority expansion creates a reachable hazardous path.'}</dd>
                  <dt>Shortest hazardous trajectory</dt>
                  <dd>{(selectedPath?.path?.nodes || []).length || trajectories[0]?.path?.nodes?.length || '—'} transitions</dd>
                  <dt>Mode</dt>
                  <dd>{String(enforcement.mode || '').toUpperCase()}</dd>
                  <dt>Reachability depth</dt>
                  <dd>{Number(session?.analysis_bounds?.max_depth ?? eventDetail?.max_depth ?? '—')}</dd>
                  <dt>Graph nodes</dt>
                  <dd>{Number(fullGraph.nodes?.length || 0)}</dd>
                  <dt>Graph edges</dt>
                  <dd>{Number(fullGraph.edges?.length || 0)}</dd>
                  <dt>Analysis</dt>
                  <dd>
                    {String(session?.analysis_status || eventDetail?.analysis_status || '—').toUpperCase()}
                    {session?.analysis_incomplete_reason || eventDetail?.analysis_incomplete_reason
                      ? ` — ${session?.analysis_incomplete_reason || eventDetail?.analysis_incomplete_reason}`
                      : ''}
                  </dd>
                  {String(session?.analysis_status || '').toLowerCase() === 'truncated' ||
                  String(eventDetail?.analysis_status || '').toLowerCase() === 'truncated' ? (
                    <>
                      <dt>Safe conclusion</dt>
                      <dd>No — incomplete analysis is never treated as safe.</dd>
                    </>
                  ) : null}
                </dl>
                {onOpenDecision && eventDetail?.event_id ? (
                  <button type="button" className="button button--ghost" onClick={() => onOpenDecision(Number(eventDetail.event_id))}>
                    Open decision {eventDetail.event_id}
                  </button>
                ) : null}
              </div>
            ) : null}
            {inspectorFocus === 'node' && selectedNode ? (
              <div data-testid="inspector-node">
                <h3>{humanizeLabel(selectedNode).title}</h3>
                <dl className="paDl">
                  <dt>Identifier</dt>
                  <dd>{String(selectedNode.label || nid(selectedNode))}</dd>
                  <dt>Type</dt>
                  <dd>{selectedNode.node_type || selectedNode.kind}</dd>
                  <dt>State</dt>
                  <dd>{nodeState(selectedNode)}</dd>
                  <dt>Column</dt>
                  <dd>{columnFor(selectedNode)}</dd>
                  <dt>Trust domain</dt>
                  <dd>{selectedNode.trustDomain || '—'}</dd>
                  <dt>Sensitive</dt>
                  <dd>{selectedNode.sensitive ? 'yes' : 'no'}</dd>
                  <dt>Predicted?</dt>
                  <dd>{isPotentialNode(selectedNode) ? 'yes — not observed as confirmed' : 'no'}</dd>
                </dl>
              </div>
            ) : null}
            {inspectorFocus === 'edge' && selectedEdge ? (
              <div data-testid="inspector-edge">
                <h3>
                  {esrc(selectedEdge)} → {edst(selectedEdge)}
                </h3>
                <dl className="paDl">
                  <dt>Relationship</dt>
                  <dd>{selectedEdge.relationship || selectedEdge.kind}</dd>
                  <dt>State</dt>
                  <dd>{selectedEdge.state}</dd>
                  <dt>Evidence</dt>
                  <dd>{selectedEdge.evidenceKind || selectedEdge.evidence?.kind}</dd>
                  <dt>Source</dt>
                  <dd>{selectedEdge.evidence?.source || '—'}</dd>
                  <dt>Still valid</dt>
                  <dd>{String(selectedEdge.evidence?.still_valid ?? true)}</dd>
                  <dt>Description</dt>
                  <dd>{selectedEdge.evidence?.description || selectedEdge.label || '—'}</dd>
                </dl>
              </div>
            ) : null}
            {mode === 'before' && !selectedNode && !selectedEdge ? (
              <div data-testid="inspector-before">
                <h3>Observed state</h3>
                <p className="muted">Predicted expansion is hidden. Nothing hazardous has necessarily happened yet.</p>
                <dl className="paDl">
                  <dt>Confirmed capabilities</dt>
                  <dd>{(eventDetail?.before?.confirmed || []).join(', ') || '—'}</dd>
                  <dt>Hidden potential</dt>
                  <dd>+{(eventDetail?.before?.potential || []).length || fullGraph.nodes.filter((n) => isPotentialNode(n)).length}</dd>
                </dl>
              </div>
            ) : null}
            {inspectorFocus === 'empty' && mode !== 'before' ? <p className="muted">Load the demo or select a trajectory to inspect the security story.</p> : null}
          </aside>
        ) : (
          <button type="button" className="paInspectorPeek" onClick={() => setInspectorOpen(true)} aria-label="Open inspector">
            ›
          </button>
        )}
      </div>

      <div className="paLower">
        <div className="eyebrow">Hazardous trajectories</div>
        <div className="paTrajectories" data-testid="trajectories">
          {!trajectories.length ? <p className="muted">No hazardous trajectories in this view.</p> : null}
          {trajectories.map((t: any, i: number) => (
            <button
              key={i}
              type="button"
              className={classNames('paTrajCard', selectedPath === t && 'is-active')}
              data-testid={`trajectory-card-${i}`}
              onClick={() => selectPath(t)}
            >
              <div className="paTrajCard__head">
                <strong>
                  {i + 1}. {(t.pattern || 'hazardous_path').replace(/_/g, ' ').toUpperCase()}
                </strong>
                <span className="badge badge--danger">HIGH</span>
              </div>
              <div className="paTrajPath">{t.path?.display || t.description || t}</div>
              <div className="muted">Interrupted at: {formatDecision(enforcement?.final, enforcement?.mode)}</div>
            </button>
          ))}
        </div>

        {mode === 'delta' ? (
          <div className="paDeltaStory" data-testid="authority-delta">
            <div className="eyebrow">Authority delta</div>
            <div className="paDeltaStory__cols">
              <div>
                <div className="eyebrow">Before</div>
                <ul>{(eventDetail?.before?.confirmed || []).slice(0, 8).map((c: string) => <li key={c}>{c}</li>)}</ul>
              </div>
              <div>
                <div className="eyebrow">New</div>
                <ul>
                  {(delta?.added_capabilities || []).map((c: any) => (
                    <li key={c.name || c}>
                      {c.name || c} <em>({c.kind || 'added'})</em>
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <div className="eyebrow">Hazardous</div>
                <strong>{trajectories.length} trajectories</strong>
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

export default PredictiveAuthorityPage;
