import React, { useEffect, useMemo, useState } from 'react';
import { MetricCard } from '../ui/Cards';

type WebShieldPageProps = {
  token: string;
  onOpenPolicy: () => void;
  helpers: {
    api: <T>(path: string, opts?: RequestInit, token?: string) => Promise<T>;
    classNames: (...parts: Array<string | false | null | undefined>) => string;
    fmtNum: (value?: number | null, digits?: number) => string;
    fmtTs: (ts?: number) => string;
    displayValue: (value: any) => string;
  };
};

type Tab = 'inventory' | 'approvals' | 'sessions';

function riskTone(band?: string | null) {
  if (band === 'critical' || band === 'high') return 'danger';
  if (band === 'suspicious' || band === 'guarded') return 'warn';
  return 'ok';
}

function enforcementTone(value?: string | null) {
  if (value === 'block' || value === 'unavailable') return 'danger';
  if (value === 'require_approval' || value === 'sanitise' || value === 'warn') return 'warn';
  return 'ok';
}

function truncate(value: string, limit = 64) {
  const text = String(value || '');
  return text.length > limit ? `${text.slice(0, limit - 1)}…` : text;
}

export function WebShieldPage({ token, onOpenPolicy, helpers }: WebShieldPageProps) {
  const { api, classNames, fmtNum, fmtTs, displayValue } = helpers;
  const [overview, setOverview] = useState<any>(null);
  const [tools, setTools] = useState<any[]>([]);
  const [approvals, setApprovals] = useState<any[]>([]);
  const [sessions, setSessions] = useState<any[]>([]);
  const [config, setConfig] = useState<any>(null);
  const [selectedKey, setSelectedKey] = useState<string>('');
  const [detail, setDetail] = useState<any>(null);
  const [tab, setTab] = useState<Tab>('inventory');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  async function refreshAll() {
    if (!token) return;
    setLoading(true);
    setError('');
    try {
      const [ov, toolsPayload, approvalsPayload, sessionsPayload, cfg] = await Promise.all([
        api<any>('/webshield/overview', {}, token),
        api<any>('/webshield/tools', {}, token),
        api<any>('/webshield/approvals', { }, token).catch(() => ({ items: [] })),
        api<any>('/webshield/sessions', {}, token).catch(() => ({ items: [] })),
        api<any>('/webshield/config', {}, token).catch(() => null),
      ]);
      setOverview(ov);
      setTools(toolsPayload?.items || []);
      setApprovals(approvalsPayload?.items || []);
      setSessions(sessionsPayload?.items || []);
      setConfig(cfg);
    } catch (e: any) {
      setError(e?.message || 'Failed to load Web Shield data');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refreshAll().catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  useEffect(() => {
    if (!selectedKey) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    api<any>(`/webshield/tools/detail?identity_key=${encodeURIComponent(selectedKey)}`, {}, token)
      .then((payload) => { if (!cancelled) setDetail(payload); })
      .catch(() => { if (!cancelled) setDetail(null); });
    return () => { cancelled = true; };
  }, [selectedKey, token]);

  useEffect(() => {
    if (!selectedKey && tools.length) setSelectedKey(tools[0].identity_key);
  }, [tools, selectedKey]);

  async function resolveApproval(requestId: string, decision: string) {
    if (!token) return;
    try {
      await api<any>(`/webshield/approvals/${encodeURIComponent(requestId)}/resolve`, { method: 'POST', body: JSON.stringify({ decision }) }, token);
      setNotice(`Approval ${requestId.slice(0, 8)} resolved: ${decision.replace(/_/g, ' ')}`);
      await refreshAll();
    } catch (e: any) {
      setError(e?.message || 'Failed to resolve approval');
    }
  }

  async function importDefaultPack() {
    if (!token) return;
    try {
      const result = await api<any>('/policy/import-pack', { method: 'POST', body: JSON.stringify({ pack_id: 'webmcp-web-shield', mode: 'merge' }) }, token);
      const added = result?.added || {};
      const total = Object.values(added).reduce((sum: number, n: any) => sum + (Number(n) || 0), 0);
      setNotice(total ? `Imported the Web Shield default policy pack (${total} new rules).` : 'Web Shield default policy pack already imported.');
      await refreshAll();
    } catch (e: any) {
      setError(e?.message || 'Failed to import the Web Shield policy pack');
    }
  }

  const pendingApprovals = useMemo(() => approvals.filter((row) => row.status === 'pending'), [approvals]);
  const selectedTool = detail?.tool || null;

  return (
    <section className="pageGrid">
      {!config?.enabled ? (
        <div className="banner banner--warn">
          Web Shield policy rules are not active yet. Registrations/invocations/outputs are still being scanned and
          recorded, but no block/warn/sanitise/require-approval action will be taken until you import a policy.
          {' '}
          <button className="button button--ghost" onClick={importDefaultPack}>Import default Web Shield policy pack</button>
          {' '}
          <button className="button button--ghost" onClick={onOpenPolicy}>Open policy workspace</button>
        </div>
      ) : null}
      {error ? <div className="banner banner--error">{error}</div> : null}
      {notice ? <div className="banner banner--ok">{notice}</div> : null}

      <div className="metricsRow metricsRow--six">
        <MetricCard title="Protected Sessions" value={fmtNum(overview?.protected_sessions)} subtitle={`${fmtNum(overview?.origins_observed)} origins observed`} tone="ok" />
        <MetricCard title="Tools Registered" value={fmtNum(overview?.tools_registered)} subtitle={`${fmtNum(overview?.new_tools_24h)} new in 24h`} tone="accent" />
        <MetricCard title="Critical Findings" value={fmtNum(overview?.critical_findings)} subtitle="Registrations/outputs at critical risk" tone="danger" />
        <MetricCard title="Blocked Registrations" value={fmtNum(overview?.blocked_registrations)} subtitle={`${fmtNum(overview?.sanitised_registrations)} sanitised`} tone="warn" />
        <MetricCard title="Pending Approvals" value={fmtNum(pendingApprovals.length)} subtitle="Awaiting operator decision" tone={pendingApprovals.length ? 'warn' : 'ok'} onClick={() => setTab('approvals')} />
        <MetricCard title="Cross-Origin Alerts" value={fmtNum(overview?.cross_origin_alerts)} subtitle={`${fmtNum(overview?.contaminated_outputs)} contaminated outputs`} tone="warn" />
      </div>

      <div className="card">
        <div className="sectionHeader sectionHeader--tight">
          <div>
            <div className="eyebrow">Varden Web Shield</div>
            <h3>Browser WebMCP tool surface</h3>
          </div>
          <div className="toggleRow">
            {(['inventory', 'approvals', 'sessions'] as Tab[]).map((value) => (
              <button
                key={value}
                className={classNames('segmented', tab === value && 'is-active')}
                onClick={() => setTab(value)}
              >
                {value === 'inventory' ? `Tool inventory (${tools.length})` : value === 'approvals' ? `Approvals (${pendingApprovals.length})` : `Sessions (${sessions.length})`}
              </button>
            ))}
            <button className="button button--ghost" onClick={() => refreshAll().catch(() => {})} disabled={loading}>
              {loading ? 'Refreshing…' : 'Refresh'}
            </button>
          </div>
        </div>
        <p className="muted">
          Runtime governance and tool-surface security for browser agents: every WebMCP tool a page registers, every
          invocation an agent makes, and every result a tool returns is normalised, scanned by seven layered
          classifiers and scored before policy decides what happens next.
        </p>
      </div>

      {tab === 'inventory' ? (
        <section className="layout layout--twoThirds">
          <div className="card">
            <div className="sectionHeader sectionHeader--tight">
              <div><div className="eyebrow">Tool inventory</div><h3>Registered WebMCP tools</h3></div>
            </div>
            {tools.length ? (
              <div className="webshieldList">
                {tools.map((tool) => (
                  <button
                    key={tool.identity_key}
                    type="button"
                    className={classNames('webshieldRow', selectedKey === tool.identity_key && 'is-active')}
                    onClick={() => setSelectedKey(tool.identity_key)}
                  >
                    <div className={classNames('webshieldRow__dot', `is-${riskTone(tool.risk_band)}`)} />
                    <div className="webshieldRow__body">
                      <div className="webshieldRow__headline">
                        <strong>{tool.tool_name}</strong>
                        <span className={classNames('badge', `badge--${riskTone(tool.risk_band)}`)}>{tool.risk_band} · {tool.risk_score}</span>
                      </div>
                      <div className="traceCard__meta">
                        {tool.owner_origin} · {tool.status} · seen {fmtNum(tool.registration_count)}x · last {fmtTs(tool.last_seen_at)}
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            ) : (
              <div className="emptyState">
                <strong>No WebMCP tools observed yet.</strong>
                <span className="muted">Run <code>varden web-shield demo</code> to seed the attack lab, or connect the browser extension/SDK.</span>
              </div>
            )}
          </div>
          <div className="card">
            {selectedTool ? (
              <>
                <div className="sectionHeader sectionHeader--tight">
                  <div>
                    <div className="eyebrow">Tool detail</div>
                    <h3>{selectedTool.tool_name}</h3>
                  </div>
                  <span className={classNames('badge', `badge--${riskTone(selectedTool.risk_band)}`)}>{selectedTool.risk_band} · {selectedTool.risk_score}</span>
                </div>
                <div className="detailGrid">
                  <div className="stat"><span>Owner origin</span><strong>{selectedTool.owner_origin}</strong></div>
                  <div className="stat"><span>API surface</span><strong>{selectedTool.api_surface}</strong></div>
                  <div className="stat"><span>Trust state</span><strong>{selectedTool.trust_state || 'none'}</strong></div>
                </div>
                <div className="subheading">Findings</div>
                {(selectedTool.findings || []).length ? (
                  <div className="stack">
                    {selectedTool.findings.map((finding: any) => (
                      <div key={finding.rule_id + finding.field_path} className="webshieldFinding">
                        <div className="webshieldFinding__head">
                          <span className={classNames('badge', `badge--${riskTone(finding.severity === 'critical' || finding.severity === 'high' ? 'critical' : finding.severity)}`)}>{finding.severity}</span>
                          <strong>{finding.rule_id}</strong>
                          <span className="muted">{finding.field_path}</span>
                        </div>
                        <p className="muted">{finding.explanation}</p>
                        <div className="codeCard"><pre>{truncate(finding.evidence, 160)}</pre></div>
                        {finding.remediation ? <p className="muted">Remediation: {finding.remediation}</p> : null}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="muted">No findings recorded for this tool.</p>
                )}
                <div className="subheading" style={{ marginTop: 16 }}>Lifecycle timeline</div>
                <div className="stack">
                  {(detail?.timeline || []).slice(0, 20).map((event: any) => (
                    <div key={event.id} className="webshieldTimelineRow">
                      <span className={classNames('badge', `badge--${enforcementTone(event.requested_enforcement)}`)}>{event.event_type.replace('webmcp.', '')}</span>
                      <span className="muted">{fmtTs(event.timestamp)}</span>
                      <span className="muted">risk {event.risk_band || '—'}</span>
                      <span className="muted">requested: {event.requested_enforcement || 'allow'} · achieved: {event.achieved_enforcement || 'allow'}</span>
                    </div>
                  ))}
                  {!detail?.timeline?.length ? <p className="muted">No lifecycle events recorded yet.</p> : null}
                </div>
              </>
            ) : (
              <div className="emptyState">
                <strong>No tool selected.</strong>
                <span className="muted">Choose a tool from the inventory to see its findings, risk explanation and lifecycle timeline.</span>
              </div>
            )}
          </div>
        </section>
      ) : null}

      {tab === 'approvals' ? (
        <div className="card">
          <div className="sectionHeader sectionHeader--tight">
            <div><div className="eyebrow">Approvals</div><h3>Pending and resolved approval requests</h3></div>
          </div>
          {approvals.length ? (
            <div className="stack">
              {approvals.map((approval) => (
                <div key={approval.request_id} className="webshieldApprovalRow">
                  <div className="webshieldApprovalRow__body">
                    <div className="webshieldRow__headline">
                      <strong>{approval.tool_name}</strong>
                      <span className={classNames('badge', `badge--${riskTone(approval.risk_band)}`)}>{approval.risk_band} · {approval.risk_score}</span>
                      <span className={classNames('badge', approval.status === 'pending' ? 'badge--warn' : 'badge--ok')}>{approval.status}</span>
                    </div>
                    <div className="traceCard__meta">{approval.owner_origin} · {approval.reason}</div>
                  </div>
                  {approval.status === 'pending' ? (
                    <div className="toggleRow">
                      <button className="button button--ghost" onClick={() => resolveApproval(approval.request_id, 'allow_once')}>Allow once</button>
                      <button className="button button--ghost" onClick={() => resolveApproval(approval.request_id, 'allow_session')}>Allow session</button>
                      <button className="button" onClick={() => resolveApproval(approval.request_id, 'trust_origin')}>Trust origin</button>
                      <button className="button button--ghost" onClick={() => resolveApproval(approval.request_id, 'deny_once')}>Deny</button>
                      <button className="button button--danger" onClick={() => resolveApproval(approval.request_id, 'block_origin')}>Block origin</button>
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          ) : (
            <div className="emptyState">
              <strong>No approval requests.</strong>
              <span className="muted">High-risk registrations and invocations that require approval will appear here.</span>
            </div>
          )}
        </div>
      ) : null}

      {tab === 'sessions' ? (
        <div className="card">
          <div className="sectionHeader sectionHeader--tight">
            <div><div className="eyebrow">Sessions</div><h3>Protected browser sessions</h3></div>
          </div>
          {sessions.length ? (
            <div className="stack">
              {sessions.map((session) => (
                <div key={session.session_id} className="webshieldTimelineRow">
                  <strong>{session.session_id}</strong>
                  <span className="muted">{session.top_origin || 'unknown origin'}</span>
                  <span className={classNames('badge', session.connected ? 'badge--ok' : 'badge--warn')}>{session.connected ? 'connected' : session.protection_mode || 'local fallback'}</span>
                  <span className="muted">last seen {fmtTs(session.last_seen_at)}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="emptyState">
              <strong>No sessions recorded.</strong>
              <span className="muted">Sessions appear once a browser tab registers a WebMCP tool or the extension reports health.</span>
            </div>
          )}
        </div>
      ) : null}

      <div className="card">
        <div className="subheading">Raw overview payload</div>
        <div className="codeCard"><pre>{displayValue(overview)}</pre></div>
      </div>
    </section>
  );
}
