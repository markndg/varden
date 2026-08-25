import React, { useEffect, useMemo, useState } from 'react';
import { MetricCard } from '../ui/Cards';
import {
  AttackPathNode,
  Incident,
  blockNodeIsClean,
  decisionLabel,
  decisionTone,
  effectiveDecision,
  findingChips,
  findingLabel,
  formatTs,
  kindLabel,
  pathPreviewText,
  pathRouteLabels,
  relativeTime,
  severityTone,
  shouldShowInvestigation,
  trustBoundaryLabel,
  trustLabel,
} from '../../lib/authorityUi';

type Helpers = {
  api: (path: string, init?: any, token?: string) => Promise<any>;
  classNames: (...parts: any[]) => string;
  token?: string;
};

type Tab = 'overview' | 'incidents' | 'paths' | 'map' | 'coverage';
type EvidenceTab = 'explanation' | 'findings' | 'policy' | 'evidence' | 'raw';

function fmt(n: any) {
  const v = Number(n || 0);
  return Number.isFinite(v) ? String(v) : '0';
}

function truncate(value: string, limit = 72) {
  const text = String(value || '');
  return text.length > limit ? `${text.slice(0, limit - 1)}…` : text;
}

function displayDecision(incident: { decision?: string; display_decision?: string }) {
  return effectiveDecision(incident);
}

function AttackPathView({
  nodes,
  classNames,
  selectedId,
  onSelect,
  lineageMeta,
}: {
  nodes: AttackPathNode[];
  classNames: Helpers['classNames'];
  selectedId?: string | null;
  onSelect?: (node: AttackPathNode) => void;
  lineageMeta?: Incident['attack_path_meta'];
}) {
  if (!nodes?.length) {
    return (
      <div className="emptyState emptyState--compact">
        <strong>No causal path available</strong>
        <span className="muted">This event was observed without sufficient provenance to reconstruct a security-relevant path.</span>
      </div>
    );
  }
  return (
    <div>
      <ol className="attackPath" aria-label="Attack path">
        {nodes.map((node, idx) => {
          const isBlock = node.kind === 'block' || node.kind === 'approval' || node.kind === 'enforcement';
          const isAllow = node.kind === 'allow';
          return (
            <li key={node.id || `${node.kind}-${idx}`} className="attackPath__step">
              <button
                type="button"
                className={classNames(
                  'attackPath__node',
                  `attackPath__node--${node.kind || 'tool'}`,
                  node.trust && `is-trust-${node.trust}`,
                  node.sensitivity && `is-sens-${node.sensitivity}`,
                  isBlock && 'attackPath__node--block',
                  isAllow && 'attackPath__node--allow',
                  selectedId === node.id && 'is-selected',
                )}
                onClick={() => onSelect?.(node)}
                aria-pressed={selectedId === node.id}
              >
                <div className="attackPath__nodeMeta">
                  <span className="attackPath__kind">{kindLabel(node.kind)}</span>
                  {node.trust ? <span className={classNames('trustPill', `trustPill--${node.trust}`)}>{trustLabel(node.trust)}</span> : null}
                  {node.capability ? <span className={classNames('capPill', `capPill--${node.capability}`)}>{String(node.capability).toUpperCase()}</span> : null}
                  {node.sensitivity && node.sensitivity !== 'public' ? (
                    <span className={classNames('sensPill', `sensPill--${node.sensitivity}`)}>
                      {node.sensitivity === 'secret' ? 'SECRET ACCESS' : String(node.sensitivity).toUpperCase()}
                    </span>
                  ) : null}
                </div>
                <strong className="attackPath__label">{truncate(String(node.label || '—'), 64)}</strong>
                {node.subtitle ? <span className="attackPath__sub muted">{truncate(String(node.subtitle), 80)}</span> : null}
                {node.technical_id && node.technical_id !== node.label ? (
                  <span className="attackPath__tech muted">{truncate(String(node.technical_id), 72)}</span>
                ) : null}
              </button>
              {idx < nodes.length - 1 ? (
                <div className={classNames('attackPath__edge', isBlock && 'attackPath__edge--stop')} aria-hidden="true">
                  <span>{node.edge_to_next || 'then'}</span>
                </div>
              ) : null}
            </li>
          );
        })}
      </ol>
      {lineageMeta?.truncated ? (
        <p className="muted lineageNote" role="status">
          Showing {lineageMeta.shown} of {lineageMeta.total_observed} observed nodes. Traversal limited by safety bound
          {lineageMeta.bound ? ` (${lineageMeta.bound})` : ''}. Truncated graph is not complete.
        </p>
      ) : null}
    </div>
  );
}

function CompactPathRoute({ route }: { route: string[] }) {
  if (!route.length) return null;
  return (
    <ol className="pathIndex__route" aria-label="Causal route">
      {route.map((step, idx) => {
        const isTerminal = idx === route.length - 1 && /blocked|allowed|monitored|warned|sanitised|approval/i.test(step);
        return (
          <li key={`${step}-${idx}`} className={classNamesSafe(isTerminal && 'is-terminal')}>
            {idx > 0 && !isTerminal ? <span className="pathIndex__arrow" aria-hidden="true">→</span> : null}
            {isTerminal && idx > 0 ? <span className="pathIndex__arrow" aria-hidden="true">✕</span> : null}
            <span>{step}</span>
          </li>
        );
      })}
    </ol>
  );
}

function classNamesSafe(...parts: any[]) {
  return parts.filter(Boolean).join(' ');
}

function AuthorityMismatch({ authority, classNames }: { authority?: Incident['authority']; classNames: Helpers['classNames'] }) {
  const required = authority?.required || [];
  const granted = authority?.granted || [];
  const missing = new Set(authority?.missing || []);
  const reasons = authority?.required_reasons || {};
  if (!required.length && !granted.length) {
    return (
      <div className="emptyState emptyState--compact">
        <strong>Authority classification unavailable</strong>
        <span className="muted">This integration did not provide enough information to classify the requested capability.</span>
      </div>
    );
  }
  return (
    <div className="authMismatch" aria-label="Authority mismatch">
      <div className="authMismatch__col">
        <div className="eyebrow">Delegated for this chain</div>
        <ul className="authMismatch__list">
          {granted.length ? granted.map((cap) => (
            <li key={cap} className="authMismatch__item authMismatch__item--ok">
              <span aria-hidden="true">✓</span> {cap}
            </li>
          )) : <li className="muted">NONE</li>}
        </ul>
      </div>
      <div className="authMismatch__divider" aria-hidden="true">
        <span className={classNames('authMismatch__verdict', missing.size || authority?.violation ? 'is-denied' : 'is-ok')}>
          {missing.size || authority?.violation ? 'NOT AUTHORISED' : 'AUTHORISED'}
        </span>
      </div>
      <div className="authMismatch__col">
        <div className="eyebrow">Required</div>
        <ul className="authMismatch__list">
          {required.length ? required.map((cap) => (
            <li
              key={cap}
              className={classNames(
                'authMismatch__item',
                missing.has(cap) ? 'authMismatch__item--missing' : 'authMismatch__item--ok',
              )}
            >
              <div className="authMismatch__cap">
                <span aria-hidden="true">{missing.has(cap) ? '✕' : '✓'}</span> {cap}
              </div>
              {reasons[cap] ? <div className="authMismatch__why muted">{reasons[cap]}</div> : (
                <div className="authMismatch__why muted">No classifier rationale recorded for this capability.</div>
              )}
            </li>
          )) : <li className="muted">NONE</li>}
        </ul>
      </div>
    </div>
  );
}

function IncidentCard({
  incident,
  classNames,
  active,
  onOpen,
}: {
  incident: Incident;
  classNames: Helpers['classNames'];
  active?: boolean;
  onOpen: () => void;
}) {
  const path = pathPreviewText(incident);
  const chips = findingChips(incident.findings, 3);
  const decision = displayDecision(incident);
  const quiet = Boolean(incident.quiet) || (incident.decision === 'allowed' || incident.decision === 'monitored') && !incident.finding_count && !incident.sanitiser;

  return (
    <button
      type="button"
      className={classNames(
        'incidentCard',
        active && 'is-active',
        `is-${decisionTone(decision)}`,
        quiet && 'incidentCard--quiet',
        incident.severity === 'critical' && incident.decision === 'blocked' && 'incidentCard--critical',
      )}
      onClick={onOpen}
      aria-current={active ? 'true' : undefined}
    >
      <div className="incidentCard__head">
        {!quiet ? (
          <span className={classNames('sevTag', `sevTag--${severityTone(incident.severity)}`)}>
            {String(incident.severity || 'info').toUpperCase()}
          </span>
        ) : null}
        <span className={classNames('badge', `badge--${decisionTone(decision)}`)}>
          {quiet && (decision === 'allowed' || decision === 'monitored') ? '✓ ' : ''}
          {decisionLabel(decision)}
        </span>
      </div>
      <strong className="incidentCard__title">{incident.title || 'Incident'}</strong>
      {!quiet ? (
        <div className="incidentCard__action muted">
          {incident.tool || incident.action_type || 'action'}
          {incident.resource ? <span> · {truncate(String(incident.resource), 48)}</span> : null}
        </div>
      ) : (
        <div className="incidentCard__action muted">
          {truncate(String(incident.resource || incident.tool || ''), 56)}
        </div>
      )}
      {!quiet && path ? <div className="incidentCard__path">{path}</div> : null}
      <div className="incidentCard__foot">
        {!quiet && Number(incident.finding_count) > 0 ? (
          <span className="findingChips">
            <span className="muted">{fmt(incident.finding_count)} findings</span>
            {chips.visible.map((label) => (
              <span key={label} className="findingChip">{label}</span>
            ))}
            {chips.extra > 0 ? <span className="findingChip findingChip--more">+{chips.extra}</span> : null}
          </span>
        ) : <span />}
        <span className="muted" title={formatTs(incident.timestamp) || undefined}>{relativeTime(incident.timestamp)}</span>
      </div>
    </button>
  );
}

function PathIndexCard({
  incident,
  classNames,
  active,
  onOpen,
}: {
  incident: Incident;
  classNames: Helpers['classNames'];
  active?: boolean;
  onOpen: () => void;
}) {
  const decision = displayDecision(incident);
  const route = pathRouteLabels(incident);
  const missing = incident.path_index?.missing || incident.authority?.missing || [];
  return (
    <button
      type="button"
      className={classNames('pathIndexCard', active && 'is-active', `is-${decisionTone(decision)}`)}
      onClick={onOpen}
      aria-current={active ? 'true' : undefined}
    >
      <div className="incidentCard__head">
        <span className={classNames('sevTag', `sevTag--${severityTone(incident.severity)}`)}>
          {String(incident.severity || 'info').toUpperCase()}
        </span>
        <span className={classNames('badge', `badge--${decisionTone(decision)}`)}>{decisionLabel(decision)}</span>
      </div>
      <strong className="pathIndexCard__title">{incident.title}</strong>
      <CompactPathRoute route={route} />
      {missing.length ? (
        <div className="pathIndexCard__missing muted">Missing: {missing.join(', ')}</div>
      ) : null}
      <div className="pathIndexCard__foot muted" title={formatTs(incident.timestamp) || undefined}>
        {relativeTime(incident.timestamp)}
      </div>
    </button>
  );
}

function InvestigationPanel({
  incident,
  classNames,
  onClose,
  showFullLineage,
  onToggleLineage,
}: {
  incident: Incident;
  classNames: Helpers['classNames'];
  onClose: () => void;
  showFullLineage: boolean;
  onToggleLineage: () => void;
}) {
  const [evidenceTab, setEvidenceTab] = useState<EvidenceTab>('explanation');
  const [selectedNode, setSelectedNode] = useState<AttackPathNode | null>(null);
  const nodes = showFullLineage ? (incident.attack_path_full || incident.attack_path || []) : (incident.attack_path || []);
  const lineageMeta = showFullLineage ? incident.attack_path_full_meta : incident.attack_path_meta;
  const complete = incident.provenance?.complete !== false;
  const explanation = incident.explanation;
  const outcome = incident.outcome || explanation?.outcome;
  const decision = displayDecision(incident);

  useEffect(() => {
    setEvidenceTab('explanation');
    setSelectedNode(null);
  }, [incident.id]);

  const dirtyBlock = (incident.attack_path || []).some((n) => !blockNodeIsClean(n));

  return (
    <aside className="investigation" aria-label="Incident investigation">
      <div className="investigation__header">
        <div>
          <div className="incidentCard__head">
            <span className={classNames('badge', `badge--${decisionTone(decision)}`)}>{decisionLabel(decision)}</span>
            <span className={classNames('sevTag', `sevTag--${severityTone(incident.severity)}`)}>
              {String(incident.severity || 'info').toUpperCase()}
            </span>
          </div>
          <h3>{incident.title}</h3>
          <p className="muted">
            {incident.tool || incident.action_type}
            {incident.resource ? ` · ${incident.resource}` : ''}
          </p>
          <p className="muted">
            {formatTs(incident.timestamp)}
            {incident.trace_id ? ` · Trace ${incident.trace_id}` : ''}
          </p>
        </div>
        <button type="button" className="button button--ghost" onClick={onClose}>Close</button>
      </div>

      {!complete ? (
        <div className="banner banner--warn provenancePartial" role="status">
          <strong>PARTIAL PROVENANCE</strong>
          <span>Complete ancestry could not be established.</span>
          <span className="muted">Unknown ancestry is never treated as trusted.</span>
        </div>
      ) : null}

      {outcome?.label ? (
        <div
          className={classNames(
            'outcomeBanner',
            outcome.side_effect_prevented === true && 'outcomeBanner--stopped',
            outcome.side_effect_prevented == null && outcome.enforced === false && 'outcomeBanner--observed',
            (incident.decision === 'allowed' || incident.decision === 'monitored' || decision === 'sanitised') && 'outcomeBanner--ok',
          )}
          role="status"
        >
          <strong>{outcome.label}</strong>
          <span>{outcome.detail}</span>
        </div>
      ) : null}

      {incident.decision === 'approval_required' ? (
        <div className="banner banner--warn" role="status">
          Approval must be completed through a supported control-plane workflow. This UI does not resume execution.
        </div>
      ) : null}

      {dirtyBlock ? (
        <div className="banner banner--warn" role="status">Evidence warning: block node carried unexpected trust/sensitivity labels.</div>
      ) : null}

      <section className="card card--nested">
        <div className="sectionHeader sectionHeader--tight">
          <div>
            <div className="eyebrow">Attack path</div>
            <h4>Security-relevant causal chain</h4>
          </div>
          <button type="button" className="button button--ghost" onClick={onToggleLineage}>
            {showFullLineage ? 'Show minimal path' : 'Show full lineage'}
          </button>
        </div>
        <AttackPathView
          nodes={nodes}
          classNames={classNames}
          selectedId={selectedNode?.id}
          onSelect={setSelectedNode}
          lineageMeta={lineageMeta}
        />
        {selectedNode ? (
          <div className="nodeDetail" role="region" aria-label="Selected path node">
            <div className="eyebrow">{kindLabel(selectedNode.kind)}</div>
            <strong>{selectedNode.label}</strong>
            {selectedNode.subtitle ? <p className="muted">{selectedNode.subtitle}</p> : null}
            {selectedNode.technical_id ? <p className="muted codeInline">{selectedNode.technical_id}</p> : null}
            <div className="detailGrid">
              {selectedNode.trust ? <div className="stat"><span>Trust</span><strong>{trustLabel(selectedNode.trust)}</strong></div> : null}
              {selectedNode.capability ? <div className="stat"><span>Capability</span><strong>{String(selectedNode.capability).toUpperCase()}</strong></div> : null}
              {selectedNode.sensitivity ? <div className="stat"><span>Sensitivity</span><strong>{String(selectedNode.sensitivity).toUpperCase()}</strong></div> : null}
            </div>
          </div>
        ) : null}
      </section>

      <section className="card card--nested">
        <div className="eyebrow">Authority</div>
        <h4>Delegated vs required</h4>
        <AuthorityMismatch authority={incident.authority} classNames={classNames} />
      </section>

      <section className="card card--nested">
        <div className="eyebrow">Why Varden {incident.decision === 'blocked' ? 'blocked' : incident.decision === 'allowed' || incident.decision === 'monitored' || decision === 'sanitised' ? 'allowed' : 'decided on'} this</div>
        <div className="whyBlock">
          {(explanation?.text || incident.why || incident.summary || '').split(/\n\n+/).map((para, i) => (
            <p key={i}>{para}</p>
          ))}
        </div>
      </section>

      <section className="card card--nested">
        <div className="toggleRow" role="tablist" aria-label="Evidence tabs">
          {([
            ['explanation', 'Explanation'],
            ['findings', 'Findings'],
            ['policy', 'Policy'],
            ['evidence', 'Evidence'],
            ['raw', 'Raw'],
          ] as const).map(([id, label]) => (
            <button
              key={id}
              type="button"
              role="tab"
              aria-selected={evidenceTab === id}
              className={classNames('segmented', evidenceTab === id && 'is-active')}
              onClick={() => setEvidenceTab(id)}
            >
              {label}
            </button>
          ))}
        </div>
        {evidenceTab === 'explanation' ? (
          <div className="stack" style={{ marginTop: 12 }}>
            <p>{explanation?.summary || incident.summary}</p>
            {explanation?.decision_reason ? <p className="muted">{explanation.decision_reason}</p> : null}
          </div>
        ) : null}
        {evidenceTab === 'findings' ? (
          <ul className="findingList" style={{ marginTop: 12 }}>
            {(incident.findings || []).length ? (incident.findings || []).map((f) => (
              <li key={f.type}>
                <strong>{findingLabel(f)}</strong>
                <span className="muted"> — {f.blurb || f.explanation}</span>
                <div className="codeInline muted">Finding: {f.type}</div>
              </li>
            )) : <li className="muted">No security findings on this incident.</li>}
          </ul>
        ) : null}
        {evidenceTab === 'policy' ? (
          <div className="stack" style={{ marginTop: 12 }}>
            <div className="stat"><span>Enforcement</span><strong>{decisionLabel(decision)}</strong></div>
            <div className="stat"><span>Rule</span><strong>{incident.policy?.rule_id || '—'}</strong></div>
            <div className="stat"><span>Policy</span><strong>{incident.policy?.pack || '—'}</strong></div>
            <div className="stat"><span>Matched because</span><strong>{incident.policy?.reason || explanation?.decision_reason || '—'}</strong></div>
            <details className="evidenceDetails">
              <summary>Matched rule object</summary>
              <pre className="editor editor--compact">{JSON.stringify(incident.policy?.matched_rule || {}, null, 2)}</pre>
            </details>
          </div>
        ) : null}
        {evidenceTab === 'evidence' ? (
          <div className="stack" style={{ marginTop: 12 }}>
            <div className="detailGrid">
              <div className="stat"><span>Provenance trust</span><strong>{trustLabel(incident.provenance?.trust) || '—'}</strong></div>
              <div className="stat"><span>Complete</span><strong>{complete ? 'yes' : 'no'}</strong></div>
              <div className="stat"><span>Findings</span><strong>{fmt(incident.finding_count)}</strong></div>
              <div className="stat"><span>Enforcement</span><strong>{incident.enforcement?.surface || outcome?.basis || '—'}</strong></div>
            </div>
            <pre className="editor editor--compact">{JSON.stringify({
              sources: incident.sources,
              authority: incident.authority,
              provenance: incident.provenance,
              enforcement: incident.enforcement,
              outcome: incident.outcome,
              taint: (incident as any).taint,
            }, null, 2)}</pre>
          </div>
        ) : null}
        {evidenceTab === 'raw' ? (
          <pre className="editor editor--compact" style={{ marginTop: 12 }}>{JSON.stringify(incident, null, 2)}</pre>
        ) : null}
      </section>
    </aside>
  );
}

function ReachabilityMap({
  authorityMap,
  classNames,
  highlightIds,
  selectedExplainId,
  onSelectExplain,
}: {
  authorityMap: any;
  classNames: Helpers['classNames'];
  highlightIds: Set<string>;
  selectedExplainId: string | null;
  onSelectExplain: (id: string | null, payload?: any) => void;
}) {
  const lanes = authorityMap?.lanes || [];
  const nodes: any[] = authorityMap?.nodes || [];
  const byLane: Record<string, any[]> = {};
  for (const lane of lanes) {
    byLane[lane.id] = nodes.filter((n) => n.lane === lane.id);
  }
  if (!nodes.length) {
    return (
      <div className="emptyState emptyState--compact">
        <strong>No reachability evidence yet.</strong>
        <span className="muted">Guarded actions and MCP fingerprints populate this map.</span>
      </div>
    );
  }

  function renderNode(node: any) {
    const hot = highlightIds.size ? highlightIds.has(node.id) : true;
    const dim = highlightIds.size > 0 && !hot;
    return (
      <button
        key={node.id}
        type="button"
        className={classNames(
          'reachMap__node',
          `reachMap__node--${node.trust_boundary || node.kind || 'default'}`,
          hot && highlightIds.size > 0 && 'is-hot',
          dim && 'is-dim',
          selectedExplainId === node.id && 'is-selected',
        )}
        onClick={() => onSelectExplain(node.id, { type: 'node', ...node })}
      >
        {node.trust_boundary ? (
          <span className="reachMap__boundary">{trustBoundaryLabel(node.trust_boundary)}</span>
        ) : null}
        <strong>{node.label}</strong>
        {(node.capabilities || []).length ? (
          <span className="muted">{(node.capabilities || []).slice(0, 3).join(' · ')}</span>
        ) : null}
      </button>
    );
  }

  return (
    <div className="reachMap" aria-label="Authority reachability map">
      <p className="muted reachMap__disclaimer">
        Architectural reachability from observed evidence — not delegated authority.
        An untrusted input influencing the agent does not mean it is authorised to reach every destination.
      </p>
      <div className="reachMap__flow" aria-hidden="false">
        <div className="reachMap__lane reachMap__lane--inputs">
          <div className="reachMap__laneTitle">Inputs</div>
          <div className="reachMap__laneNodes">{(byLane.inputs || []).map(renderNode)}</div>
        </div>
        <div className="reachMap__connector" aria-hidden="true"><span>influences</span></div>
        <div className="reachMap__lane reachMap__lane--agent">
          <div className="reachMap__laneTitle">Agent</div>
          <div className="reachMap__laneNodes">{(byLane.agent || []).map(renderNode)}</div>
        </div>
        <div className="reachMap__connector" aria-hidden="true"><span>can reach</span></div>
        <div className="reachMap__lane reachMap__lane--domains">
          <div className="reachMap__laneTitle">Capability domains</div>
          <div className="reachMap__laneNodes">{(byLane.domains || []).map(renderNode)}</div>
        </div>
        <div className="reachMap__connector" aria-hidden="true"><span>includes</span></div>
        <div className="reachMap__lane reachMap__lane--destinations">
          <div className="reachMap__laneTitle">Destinations</div>
          <div className="reachMap__laneNodes">{(byLane.destinations || []).map(renderNode)}</div>
        </div>
      </div>
      {(authorityMap?.edges || []).length ? (
        <div className="reachMap__edges">
          <div className="eyebrow">Explainable edges</div>
          <ul>
            {(authorityMap.edges || []).slice(0, 12).map((edge: any) => {
              const hot = !highlightIds.size
                || (highlightIds.has(edge.from) && highlightIds.has(edge.to));
              return (
                <li key={edge.id}>
                  <button
                    type="button"
                    className={classNames('reachMap__edgeBtn', !hot && highlightIds.size > 0 && 'is-dim', selectedExplainId === edge.id && 'is-selected')}
                    onClick={() => onSelectExplain(edge.id, { type: 'edge', ...edge })}
                  >
                    <code>{edge.from}</code>
                    <span className="muted"> {edge.relationship || '→'} </span>
                    <code>{edge.to}</code>
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

export function AuthorityProvenancePage({ helpers }: { helpers: Helpers }) {
  const { api, classNames, token } = helpers;
  const [summary, setSummary] = useState<any>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [authorityMap, setAuthorityMap] = useState<any>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [overviewInvestigationOpen, setOverviewInvestigationOpen] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState<Tab>('overview');
  const [runtimeCoverage, setRuntimeCoverage] = useState<any>(null);
  const [selectedSurface, setSelectedSurface] = useState<string | null>(null);
  const [decisionFilter, setDecisionFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [showFullLineage, setShowFullLineage] = useState(false);
  const [selectedExposureId, setSelectedExposureId] = useState<string | null>(null);
  const [explainPayload, setExplainPayload] = useState<any>(null);
  const [selectedExplainId, setSelectedExplainId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!token || tab !== 'coverage') return;
      try {
        const cov = await api('/runtime/coverage', {}, token);
        if (!cancelled) setRuntimeCoverage(cov || {});
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load runtime coverage');
      }
    })();
    return () => { cancelled = true; };
  }, [api, token, tab]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!token) return;
      setLoading(true);
      try {
        const [s, i] = await Promise.all([
          api('/provenance/summary', {}, token),
          api('/provenance/incidents?limit=100', {}, token),
        ]);
        if (cancelled) return;
        setSummary(s || {});
        setIncidents(i?.items || []);
        setError('');
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load provenance data');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [api, token]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!token) return;
      try {
        const q = selectedId ? `?incident_id=${encodeURIComponent(selectedId)}` : '';
        const m = await api(`/provenance/authority-map${q}`, {}, token);
        if (!cancelled) setAuthorityMap(m);
      } catch {
        if (!cancelled) setAuthorityMap(null);
      }
    })();
    return () => { cancelled = true; };
  }, [api, token, selectedId]);

  const selected = useMemo(
    () => incidents.find((i) => i.id === selectedId) || null,
    [incidents, selectedId],
  );

  const filteredIncidents = useMemo(() => {
    let rows = incidents;
    if (decisionFilter) {
      rows = rows.filter((i) => displayDecision(i) === decisionFilter || i.decision === decisionFilter);
    }
    if (severityFilter) {
      rows = rows.filter((i) => String(i.severity || '').toLowerCase() === severityFilter.toLowerCase());
    }
    return [...rows].sort((a, b) => {
      const rank = (i: Incident) => {
        if (i.decision === 'blocked' && i.severity === 'critical') return 0;
        if (i.decision === 'blocked') return 1;
        if (i.decision === 'approval_required') return 2;
        if (i.decision === 'warned') return 3;
        if (displayDecision(i) === 'sanitised') return 4;
        if (i.quiet) return 9;
        return 5;
      };
      return rank(a) - rank(b);
    });
  }, [incidents, decisionFilter, severityFilter]);

  const stories = (summary?.stories || incidents.filter((i) => i.decision === 'blocked' || i.severity === 'critical').slice(0, 4)) as any[];
  const exposures = authorityMap?.exposures || summary?.architectural_exposures || [];

  const highlightIds = useMemo(() => {
    const ids = new Set<string>();
    if (selectedExposureId) {
      const exp = exposures.find((e: any) => e.id === selectedExposureId);
      for (const id of exp?.highlight_node_ids || []) ids.add(id);
    }
    if (selected && tab === 'map') {
      for (const id of authorityMap?.incident_route_node_ids || []) ids.add(id);
    }
    return ids;
  }, [selectedExposureId, exposures, selected, tab, authorityMap]);

  const showInvestigation = shouldShowInvestigation(tab, selectedId, overviewInvestigationOpen);

  function openIncident(id: string, opts?: { nextTab?: Tab; fromOverview?: boolean }) {
    setSelectedId(id);
    setShowFullLineage(false);
    if (opts?.fromOverview) setOverviewInvestigationOpen(true);
    if (opts?.nextTab) setTab(opts.nextTab);
  }

  function closeInvestigation() {
    if (tab === 'overview') {
      setOverviewInvestigationOpen(false);
    } else {
      setSelectedId(null);
    }
  }

  return (
    <div className={classNames('stack', 'authorityPage', showInvestigation && 'authorityPage--split')}>
      <div className="card authorityPage__intro">
        <div className="sectionHeader sectionHeader--tight">
          <div>
            <div className="eyebrow">Authority & Provenance</div>
            <h3>Causal authority investigation</h3>
          </div>
          <div className="toggleRow" role="tablist" aria-label="Authority views">
            {([
              ['overview', 'Overview'],
              ['incidents', `Incidents${incidents.length ? ` (${incidents.length})` : ''}`],
              ['paths', 'Attack Paths'],
              ['map', 'Authority Map'],
              ['coverage', 'Protection Coverage'],
            ] as const).map(([id, label]) => (
              <button
                key={id}
                type="button"
                role="tab"
                aria-selected={tab === id}
                className={classNames('segmented', tab === id && 'is-active')}
                onClick={() => setTab(id)}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
        <p className="muted authorityPage__tagline">
          Varden does not only ask whether an agent possesses a capability. It determines whether the causal chain influencing that action was authorised to exercise it.
        </p>
        {error ? <div className="banner banner--error">{error}</div> : null}
        {loading && !summary ? <div className="muted">Loading provenance evidence…</div> : null}
      </div>

      <div className={classNames('authorityPage__body', showInvestigation && 'has-investigation')}>
        <div className="authorityPage__main stack">
          {tab === 'overview' ? (
            <>
              <div className="metricsRow authorityMetrics">
                <MetricCard title="Blocked incidents" value={fmt(summary?.blocked_incidents)} subtitle="Guarded actions stopped" tone={summary?.blocked_incidents ? 'danger' : 'ok'} onClick={() => { setDecisionFilter('blocked'); setTab('incidents'); }} />
                <MetricCard title="Critical incidents" value={fmt(summary?.critical_incidents)} subtitle="Highest severity events" tone={summary?.critical_incidents ? 'danger' : 'ok'} onClick={() => setTab('incidents')} />
                <MetricCard title="Confused deputy" value={fmt(summary?.confused_deputy_incidents)} subtitle="Untrusted influence on privilege" tone={summary?.confused_deputy_incidents ? 'danger' : 'ok'} onClick={() => setTab('incidents')} />
                <MetricCard title="Exfiltration paths" value={fmt(summary?.exfiltration_incidents)} subtitle="Sensitive data toward public sinks" tone={summary?.exfiltration_incidents ? 'warn' : 'ok'} onClick={() => setTab('paths')} />
                <MetricCard title="Cross-server flows" value={fmt(summary?.cross_server_incidents)} subtitle="MCP trust boundary crossings" tone={summary?.cross_server_incidents ? 'warn' : 'ok'} onClick={() => setTab('paths')} />
                <MetricCard title="MCP trust changes" value={fmt(summary?.stale_tool_fingerprints)} subtitle="Fingerprint drift" tone={summary?.stale_tool_fingerprints ? 'warn' : 'ok'} onClick={() => setTab('map')} />
              </div>

              <div className="card">
                <div className="sectionHeader sectionHeader--tight">
                  <div>
                    <div className="eyebrow">Guarded activity</div>
                    <h3>What Varden stopped</h3>
                  </div>
                </div>
                {stories.length ? (
                  <div className="storyGrid">
                    {stories.map((story: any) => (
                      <button
                        key={story.id}
                        type="button"
                        className="storyCard"
                        onClick={() => openIncident(story.id, { fromOverview: true })}
                      >
                        <div className="incidentCard__head">
                          <span className={classNames('sevTag', `sevTag--${severityTone(story.severity)}`)}>{String(story.severity || '').toUpperCase()}</span>
                          <span className={classNames('badge', `badge--${decisionTone(story.decision)}`)}>{decisionLabel(story.decision)}</span>
                        </div>
                        <strong>{story.title}</strong>
                        <p className="muted">{story.summary}</p>
                        {(story.path_index?.text || (story.attack_path_preview || []).length) ? (
                          <div className="incidentCard__path">
                            {story.path_index?.text || (story.attack_path_preview || []).join(' → ')}
                          </div>
                        ) : null}
                        <span className="muted" title={formatTs(story.timestamp) || undefined}>{relativeTime(story.timestamp)}</span>
                      </button>
                    ))}
                  </div>
                ) : (
                  <div className="emptyState emptyState--compact">
                    <strong>No blocked incidents yet.</strong>
                    <span className="muted">Run <code>varden provenance demo</code> to seed coherent attack stories.</span>
                  </div>
                )}
              </div>

              {exposures.length ? (
                <div className="card">
                  <div className="eyebrow">Architectural exposure</div>
                  <h3>{exposures.length} potential authority compositions deserve attention</h3>
                  <p className="muted">These are structural capability compositions — not detections that an attack occurred.</p>
                  <div className="stack">
                    {exposures.slice(0, 3).map((exp: any) => (
                      <button
                        key={exp.id || exp.title}
                        type="button"
                        className="compositionCard"
                        onClick={() => { setSelectedExposureId(exp.id); setTab('map'); }}
                      >
                        <span className={classNames('sevTag', `sevTag--${severityTone(exp.severity)}`)}>
                          {String(exp.label || 'ARCHITECTURAL EXPOSURE').toUpperCase()}
                        </span>
                        <strong>{exp.title}</strong>
                        <p className="muted">{exp.detail}</p>
                      </button>
                    ))}
                  </div>
                </div>
              ) : null}
            </>
          ) : null}

          {tab === 'incidents' ? (
            <div className="card">
              <div className="sectionHeader sectionHeader--tight">
                <div>
                  <div className="eyebrow">Incidents & decisions</div>
                  <h3>Guarded activity</h3>
                </div>
                <div className="toggleRow">
                  <label className="muted" htmlFor="decision-filter">Decision</label>
                  <select id="decision-filter" className="input" value={decisionFilter} onChange={(e) => setDecisionFilter(e.target.value)}>
                    <option value="">All</option>
                    <option value="blocked">Blocked</option>
                    <option value="approval_required">Approval required</option>
                    <option value="warned">Warned</option>
                    <option value="sanitised">Sanitised</option>
                    <option value="monitored">Monitored</option>
                    <option value="allowed">Allowed</option>
                  </select>
                </div>
              </div>
              <p className="muted">Each row is one guarded action. Allowed and warned actions remain visible — not every event is an attack.</p>
              <div className="incidentList">
                {filteredIncidents.length ? filteredIncidents.map((inc) => (
                  <IncidentCard
                    key={inc.id}
                    incident={inc}
                    classNames={classNames}
                    active={selectedId === inc.id}
                    onOpen={() => openIncident(inc.id)}
                  />
                )) : (
                  <div className="emptyState emptyState--compact">
                    <strong>No authority incidents observed</strong>
                    <span className="muted">{loading ? 'Loading…' : 'Varden has not recorded any guarded actions matching the current filters.'}</span>
                  </div>
                )}
              </div>
            </div>
          ) : null}

          {tab === 'paths' ? (
            <div className="card">
              <div className="sectionHeader sectionHeader--tight">
                <div>
                  <div className="eyebrow">Attack paths</div>
                  <h3>Path index</h3>
                </div>
                <div className="toggleRow filters--wrap">
                  <select className="input input--small" aria-label="Decision filter" value={decisionFilter} onChange={(e) => setDecisionFilter(e.target.value)}>
                    <option value="">Decision</option>
                    <option value="blocked">Blocked</option>
                    <option value="approval_required">Approval required</option>
                    <option value="warned">Warned</option>
                    <option value="sanitised">Sanitised</option>
                  </select>
                  <select className="input input--small" aria-label="Severity filter" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
                    <option value="">Severity</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                  </select>
                </div>
              </div>
              <p className="muted">Compact previews for comparison. Select a path to investigate the full causal chain on the right.</p>
              <div className="pathIndexList">
                {filteredIncidents.filter((i) => !i.quiet || i.sanitiser).length ? filteredIncidents.filter((i) => !i.quiet || i.sanitiser).map((inc) => (
                  <PathIndexCard
                    key={inc.id}
                    incident={inc}
                    classNames={classNames}
                    active={selectedId === inc.id}
                    onOpen={() => openIncident(inc.id)}
                  />
                )) : (
                  <div className="emptyState emptyState--compact">
                    <strong>No causal path available</strong>
                    <span className="muted">Incidents with provenance evidence will appear here.</span>
                  </div>
                )}
              </div>
            </div>
          ) : null}

          {tab === 'map' ? (
            <div className="stack">
              <div className="card">
                <div className="sectionHeader sectionHeader--tight">
                  <div>
                    <div className="eyebrow">Authority map</div>
                    <h3>What information influencing this agent could potentially reach</h3>
                  </div>
                </div>
                <p className="muted">{authorityMap?.note}</p>
                <ReachabilityMap
                  authorityMap={authorityMap}
                  classNames={classNames}
                  highlightIds={highlightIds}
                  selectedExplainId={selectedExplainId}
                  onSelectExplain={(id, payload) => {
                    setSelectedExplainId(id);
                    setExplainPayload(payload || null);
                  }}
                />
                {explainPayload ? (
                  <div className="nodeDetail" style={{ marginTop: 12 }} role="region" aria-label="Map explanation">
                    <div className="eyebrow">{explainPayload.type === 'edge' ? 'Edge evidence' : 'Node evidence'}</div>
                    <strong>{explainPayload.explain?.title || explainPayload.label || `${explainPayload.from} → ${explainPayload.to}`}</strong>
                    {explainPayload.explain?.detail || explainPayload.evidence?.note ? (
                      <p className="muted">{explainPayload.explain?.detail || explainPayload.evidence?.note}</p>
                    ) : null}
                    {explainPayload.explain?.trust ? <div className="stat"><span>Trust</span><strong>{String(explainPayload.explain.trust).toUpperCase()}</strong></div> : null}
                    {(explainPayload.explain?.capabilities || explainPayload.capabilities || []).length ? (
                      <div className="stat"><span>Capabilities</span><strong>{(explainPayload.explain?.capabilities || explainPayload.capabilities).join(', ')}</strong></div>
                    ) : null}
                    <pre className="editor editor--compact">{JSON.stringify(explainPayload.explain?.evidence || explainPayload.evidence || explainPayload.tools || {}, null, 2)}</pre>
                  </div>
                ) : null}
              </div>

              {authorityMap?.delegation_overlay?.rows?.length ? (
                <div className="card">
                  <div className="eyebrow">Delegation overlay</div>
                  <h3>Agent capability vs this causal chain</h3>
                  <p className="muted">{authorityMap.delegation_overlay.note}</p>
                  <table className="delegationTable">
                    <thead>
                      <tr>
                        <th>Capability</th>
                        <th>Agent possesses</th>
                        <th>This chain</th>
                      </tr>
                    </thead>
                    <tbody>
                      {authorityMap.delegation_overlay.rows.map((row: any) => (
                        <tr key={row.capability}>
                          <td><code>{row.capability}</code></td>
                          <td>{row.agent_possesses ? '✓' : '✕'}</td>
                          <td>{row.chain_delegated ? '✓' : '✕'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}

              {(exposures || []).length ? (
                <div className="card">
                  <div className="eyebrow">Architectural exposure</div>
                  <h3>Potential routes</h3>
                  <p className="muted">Selecting an exposure highlights the corresponding map nodes. This is not a detected incident.</p>
                  <div className="stack">
                    {exposures.map((comp: any) => (
                      <button
                        key={comp.id || comp.title}
                        type="button"
                        className={classNames('compositionCard', selectedExposureId === comp.id && 'is-active')}
                        onClick={() => setSelectedExposureId((cur) => (cur === comp.id ? null : comp.id))}
                      >
                        <span className={classNames('sevTag', `sevTag--${severityTone(comp.severity)}`)}>
                          {String(comp.label || 'ARCHITECTURAL EXPOSURE').toUpperCase()}
                        </span>
                        <strong>{comp.title}</strong>
                        <p className="muted">{comp.detail}</p>
                        {(comp.potential_route || []).length ? (
                          <div className="incidentCard__path">{(comp.potential_route || []).join(' → ')}</div>
                        ) : null}
                      </button>
                    ))}
                  </div>
                </div>
              ) : null}

              <div className="card">
                <div className="eyebrow">Capability inventory</div>
                <h3>Observed authority families</h3>
                <p className="muted">Secondary inventory — the map above is the primary reachability view.</p>
                <div className="authorityMap__families">
                  {Object.entries(authorityMap?.inventory || authorityMap?.families || {}).length ? Object.entries(authorityMap?.inventory || authorityMap.families).map(([family, caps]: any) => (
                    <div key={family} className="authorityMap__family">
                      <strong>{family}</strong>
                      <ul>{(caps as string[]).map((c) => <li key={c}><code>{c}</code></li>)}</ul>
                    </div>
                  )) : (
                    <div className="emptyState emptyState--compact">
                      <strong>No capability families observed yet.</strong>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ) : null}

          {tab === 'coverage' ? (
            <div className="stack">
              <div className="card">
                <div className="sectionHeader sectionHeader--tight">
                  <div>
                    <div className="eyebrow">Protection coverage</div>
                    <h3>What the runtime boundary actually enforces</h3>
                  </div>
                </div>
                <p className="muted">
                  Statuses reflect active instrumentation. This is not a vanity score — uncovered surfaces stay uncovered.
                </p>
                {(() => {
                  const live = runtimeCoverage?.live || {};
                  const categories = live.categories || [];
                  const ready = live.strict_readiness || {};
                  const bypass = live.known_bypass_surfaces || [];
                  const selected = (live.surfaces || []).find((s: any) => s.name === selectedSurface)
                    || categories.find((c: any) => c.category === selectedSurface);
                  return (
                    <>
                      <div className="coverageStatusList" role="list">
                        {categories.length ? categories.map((row: any) => (
                          <button
                            key={row.category}
                            type="button"
                            role="listitem"
                            className={classNames('coverageRow', selectedSurface === row.category && 'is-active')}
                            onClick={() => setSelectedSurface(row.category)}
                          >
                            <strong>{row.label}</strong>
                            <span className={classNames('badge', `badge--${String(row.status).includes('ENFORCED') ? 'ok' : String(row.status) === 'PARTIAL' ? 'warn' : 'danger'}`)}>
                              {row.status}
                            </span>
                          </button>
                        )) : (
                          <div className="emptyState emptyState--compact">
                            <strong>No live coverage attestation yet</strong>
                            <span className="muted">Call <code>varden.protect()</code> in a runtime process, then refresh.</span>
                          </div>
                        )}
                      </div>

                      <div className="metricsRow" style={{ marginTop: 16 }}>
                        <div className="metricCard">
                          <div className="eyebrow">Strict mode readiness</div>
                          <strong>{ready.status || 'UNKNOWN'}</strong>
                          {(ready.required_coverage_missing || []).length ? (
                            <p className="muted">Missing: {(ready.required_coverage_missing || []).join(', ')}</p>
                          ) : (
                            <p className="muted">Required interceptors present for configured coverage.</p>
                          )}
                        </div>
                      </div>

                      {selected ? (
                        <div className="nodeDetail" style={{ marginTop: 12 }}>
                          <div className="eyebrow">Surface detail</div>
                          <strong>{selected.label || selected.name || selectedSurface}</strong>
                          <p className="muted">Status: {selected.status}</p>
                          {(selected.limitations || []).length ? (
                            <ul>{(selected.limitations || []).map((lim: string) => <li key={lim} className="muted">{lim}</li>)}</ul>
                          ) : null}
                          {selected.surfaces ? (
                            <pre className="editor editor--compact">{JSON.stringify(selected.surfaces, null, 2)}</pre>
                          ) : null}
                        </div>
                      ) : null}

                      {bypass.length ? (
                        <div className="card" style={{ marginTop: 12 }}>
                          <div className="eyebrow">Known bypass surfaces</div>
                          <ul>
                            {bypass.map((s: any) => (
                              <li key={s.name}><code>{s.name}</code> — {s.status}</li>
                            ))}
                          </ul>
                        </div>
                      ) : null}
                    </>
                  );
                })()}
              </div>
            </div>
          ) : null}
        </div>

        {showInvestigation && selected ? (
          <InvestigationPanel
            key={selected.id}
            incident={selected}
            classNames={classNames}
            onClose={closeInvestigation}
            showFullLineage={showFullLineage}
            onToggleLineage={() => setShowFullLineage((v) => !v)}
          />
        ) : null}
      </div>
    </div>
  );
}
