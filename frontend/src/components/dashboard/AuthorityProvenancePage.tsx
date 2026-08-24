import React, { useEffect, useState } from 'react';

type Helpers = {
  api: (path: string, init?: any, token?: string) => Promise<any>;
  classNames: (...parts: any[]) => string;
  token?: string;
};

export function AuthorityProvenancePage({ helpers }: { helpers: Helpers }) {
  const { api, classNames, token } = helpers;
  const [summary, setSummary] = useState<any>(null);
  const [violations, setViolations] = useState<any[]>([]);
  const [flows, setFlows] = useState<any[]>([]);
  const [tools, setTools] = useState<any[]>([]);
  const [selected, setSelected] = useState<any>(null);
  const [error, setError] = useState('');
  const [tab, setTab] = useState<'summary' | 'violations' | 'flows' | 'mcp'>('summary');

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [s, v, f, t] = await Promise.all([
          api('/provenance/summary', {}, token),
          api('/authority/violations?limit=50', {}, token),
          api('/provenance/flows?limit=50', {}, token),
          api('/mcp/security/tools', {}, token),
        ]);
        if (cancelled) return;
        setSummary(s);
        setViolations(v?.items || []);
        setFlows(f?.items || []);
        setTools(t?.items || []);
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load provenance data');
      }
    })();
    return () => { cancelled = true; };
  }, [api, token]);

  return (
    <div className="stack">
      <div className="card">
        <div className="sectionHeader">
          <div>
            <div className="eyebrow">Authority & Provenance</div>
            <h3>Provenance-aware authority flow</h3>
          </div>
          <div className="toggleRow">
            {(['summary', 'violations', 'flows', 'mcp'] as const).map((id) => (
              <button key={id} type="button" className={classNames('segmented', tab === id && 'is-active')} onClick={() => setTab(id)}>
                {id === 'mcp' ? 'MCP map' : id}
              </button>
            ))}
          </div>
        </div>
        <p className="muted">
          Varden does not only ask whether an agent is allowed to use a tool. It asks whether the information that caused the tool call was authorised to exercise that tool&apos;s power.
        </p>
        {error ? <div className="banner banner--error">{error}</div> : null}
      </div>

      {tab === 'summary' && summary ? (
        <div className="card">
          <div className="templateCounts">
            <span>violations: {summary.authority_violations || 0}</span>
            <span>confused deputy: {summary.confused_deputy || 0}</span>
            <span>exfiltration chains: {summary.exfiltration_chains || 0}</span>
            <span>cross-server: {summary.cross_server_flows || 0}</span>
            <span>stale MCP fingerprints: {summary.stale_tool_fingerprints || 0}</span>
          </div>
          <div className="ruleCard__meta" style={{ marginTop: 12 }}>
            Findings by type: {Object.entries(summary.findings_by_type || {}).map(([k, v]) => `${k}=${v}`).join(' · ') || 'none yet — run `varden provenance demo`'}
          </div>
        </div>
      ) : null}

      {tab === 'violations' ? (
        <div className="card">
          <div className="sectionHeader"><div><h3>Authority violations</h3></div></div>
          <div className="coverageList">
            {violations.length ? violations.map((row) => (
              <button key={row.finding_id || row.id} type="button" className={classNames('coverageCluster', selected?.finding_id === row.finding_id && 'is-active')} onClick={() => setSelected(row)}>
                <div className="coverageCluster__body">
                  <div className="coverageCluster__headline">
                    <div>
                      <strong>{row.type}</strong>
                      <p>{row.explanation}</p>
                    </div>
                    <div className="coverageCluster__score">{row.severity}</div>
                  </div>
                  <div className="coverageCluster__meta">
                    <span>trace {row.trace_id || '—'}</span>
                    <span>{row.tool || '—'}</span>
                    <span>{row.resource || '—'}</span>
                  </div>
                </div>
              </button>
            )) : <div className="emptyState emptyState--compact"><strong>No violations recorded yet.</strong><span className="muted">Import the provenance-authority-defense pack and exercise untrusted→privileged flows.</span></div>}
          </div>
          {selected ? (
            <div className="card" style={{ marginTop: 16 }}>
              <h3>Violation detail</h3>
              <pre className="editor editor--compact" style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(selected, null, 2)}</pre>
            </div>
          ) : null}
        </div>
      ) : null}

      {tab === 'flows' ? (
        <div className="card">
          <div className="sectionHeader"><div><h3>Flow explorer</h3></div></div>
          <div className="templatePreviewList">
            {flows.length ? flows.map((flow, idx) => (
              <div key={`${flow.trace_id}:${idx}`} className="templatePreviewLine">
                <span className={classNames('badge', flow.severity === 'critical' ? 'badge--danger' : 'badge--warn')}>{flow.type}</span>
                <span>{flow.explanation}</span>
                {Array.isArray(flow.attack_path) && flow.attack_path.length ? (
                  <div className="ruleCard__meta" style={{ width: '100%' }}>{flow.attack_path.join(' → ')}</div>
                ) : null}
              </div>
            )) : <div className="muted">No cross-boundary flows recorded yet.</div>}
          </div>
        </div>
      ) : null}

      {tab === 'mcp' ? (
        <div className="card">
          <div className="sectionHeader"><div><h3>MCP authority / fingerprint map</h3></div></div>
          <div className="templatePreviewList">
            {tools.length ? tools.map((tool, idx) => (
              <div key={`${tool.server_id}:${tool.tool_name}:${idx}`} className="templatePreviewLine">
                <span className={classNames('badge', tool.trust_status === 'stale' ? 'badge--danger' : 'badge--ok')}>{tool.trust_status}</span>
                <span>{tool.server_id} / {tool.tool_name}</span>
                <span className="ruleCard__meta">{String(tool.fingerprint || '').slice(0, 16)}…</span>
              </div>
            )) : <div className="muted">No MCP tool fingerprints stored yet. Fingerprints are recorded when integrations report tool definitions.</div>}
          </div>
        </div>
      ) : null}
    </div>
  );
}
