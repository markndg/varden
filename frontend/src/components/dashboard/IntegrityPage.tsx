import React, { useEffect, useState } from 'react';
import { MetricCard } from '../ui/Cards';

type Helpers = {
  api: (path: string, init?: RequestInit, token?: string) => Promise<any>;
  token?: string;
};

type IntegrityPageProps = {
  helpers: Helpers;
};

function postureLabel(value?: string) {
  if (value === 'verified_configuration') return 'Config matches';
  if (value === 'degraded') return 'Degraded';
  if (value === 'disabled') return 'Off';
  if (value === 'unknown') return 'Unknown';
  return value || 'Unknown';
}

function toneFor(kind?: string) {
  if (kind === 'confirmed_tampering' || kind === 'degraded') return 'danger';
  if (kind === 'unknown' || kind === 'disabled') return 'warn';
  if (kind === 'verified_configuration') return 'ok';
  return undefined;
}

export function IntegrityPage({ helpers }: IntegrityPageProps) {
  const { api, token } = helpers;
  const [body, setBody] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setError(null);
    api('/runtime/integrity', {}, token)
      .then((payload) => {
        if (!cancelled) setBody(payload);
      })
      .catch((exc: any) => {
        if (!cancelled) {
          setBody(null);
          setError(exc?.message || 'Control plane did not return an integrity attestation');
        }
      });
    return () => {
      cancelled = true;
    };
  }, [api, token]);

  if (error) {
    return (
      <section className="stack">
        <div className="banner banner--warn" data-testid="integrity-unknown">
          Integrity posture is unknown. {error} This is not a clean bill of health. A gauntlet that passed for another execution is not this posture.
        </div>
      </section>
    );
  }
  if (!body) {
    return <section className="stack"><p className="muted">Loading integrity posture…</p></section>;
  }

  const analysis = body.analysis || {};
  const paths = analysis.paths || [];
  const current = paths[selected] || null;
  const interruption = current?.interruption || analysis.interruption;
  const assets = body.assets || [];
  const protectedCount = assets.filter((asset: any) => asset.protected).length;
  const boundary = body.boundary || {};
  const tier = boundary.tier || body.protection_tier || 'UNKNOWN';
  const boundaryVerified = boundary.verified === true && (tier === 'VERIFIED' || tier === 'BOUNDARY_ENFORCED');

  return (
    <section className="stack" data-testid="integrity-page">
      <div className={boundaryVerified ? 'banner' : 'banner banner--warn'} data-testid="integrity-tier">
        Protection tier: {tier}. Mechanism: {boundary.mechanism || 'not probed'}.
        {boundaryVerified
          ? ` Independent boundary verified for ${boundary.mechanism}.`
          : ' An enabled flag is not verification. In-process interception is not an OS boundary.'}
        {' '}{boundary.scope || 'No boundary scope was returned.'}
        {' '}This page is not a live supervised process. A gauntlet that passed for another execution is not this posture.
      </div>
      <div className="metricsRow">
        <MetricCard title="Posture" value={postureLabel(body.posture)} subtitle={`${tier} · ${boundary.mechanism || 'not probed'}`} tone={boundaryVerified ? 'ok' : toneFor(body.posture)} />
        <MetricCard title="Protected assets" value={protectedCount} subtitle={`${assets.length} declared`} />
        <MetricCard title="Hazardous paths" value={paths.length} subtitle={analysis.analysis_incomplete ? 'analysis incomplete' : analysis.safe_conclusion ? 'none in the completed model' : 'model result'} tone={analysis.analysis_incomplete ? 'warn' : undefined} />
        <MetricCard title="Cut proven" value={analysis.minimum_cut?.proven ? 'yes' : 'no'} subtitle={analysis.minimum_cut?.method || 'not run'} />
      </div>

      <div className="card">
        <div className="sectionHeader"><h3>Platform assurance</h3></div>
        <p className="muted">These cells are declarations for this build. A verified live execution is a different fact, and a result on one operating system is not a result on another.</p>
        <div className="stack">
          {Object.entries(body.platform_matrix || {}).map(([capability, cells]) => (
            <div key={capability} className="kv">
              <span>{capability}</span>
              <strong>{Object.entries(cells as Record<string, string>).map(([name, value]) => `${name}: ${value}`).join(' · ')}</strong>
            </div>
          ))}
          {!body.platform_matrix ? <p className="muted">No platform matrix was returned.</p> : null}
        </div>
      </div>

      <div className="card">
        <div className="sectionHeader"><h3>Enforcement boundaries</h3></div>
        <div className="stack">
          {Object.entries(body.surfaces || {}).map(([name, status]) => (
            <div key={name} className="kv"><span>{name}</span><strong>{String(status)}</strong></div>
          ))}
          {!body.surfaces ? <p className="muted">No surface attestation was returned.</p> : null}
        </div>
      </div>

      <div className="card">
        <div className="sectionHeader"><h3>Protected assets</h3></div>
        {assets.length === 0 ? <p className="muted">No assets are registered. Nothing is protected.</p> : (
          <div className="stack">
            {assets.map((asset: any) => (
              <div key={asset.id} className="kv">
                <span>{asset.id} · {asset.type} · {asset.protected ? 'protected' : 'not protected'}</span>
                <strong>{asset.verification}</strong>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <div className="sectionHeader"><h3>Invariants</h3></div>
        <div className="stack">
          {(body.invariants || []).map((item: any) => (
            <p key={item.id}><strong>{item.id}</strong> {item.summary}</p>
          ))}
          {(body.invariants || []).length === 0 ? <p className="muted">No invariants are active.</p> : null}
        </div>
      </div>

      <div className="card" data-testid="integrity-paths">
        <div className="sectionHeader"><h3>Hazardous paths</h3></div>
        {analysis.analysis_incomplete ? (
          <div className="banner banner--warn">Analysis is incomplete{analysis.incompleteness_reason ? `: ${analysis.incompleteness_reason}` : ''}. Incomplete search is not evidence of safety.</div>
        ) : null}
        {paths.length === 0 ? <p className="muted">No monitoring-integrity path was returned for the declared grants.</p> : (
          <div className="stack">
            {paths.map((path: any, index: number) => (
              <button key={path.path?.display || index} className="button button--ghost" type="button" onClick={() => setSelected(index)}>
                {path.path?.display || path.description}
              </button>
            ))}
            {interruption ? (
              <p>
                Earliest enforceable interruption: <strong>{interruption.grant_id || interruption.edge_id}</strong> on {interruption.surface || 'unknown surface'} ({interruption.outcome}).
                {interruption.enforceable ? '' : ' This step is not enforceable, so the path is not prevented.'}
              </p>
            ) : <p className="muted">No enforceable interruption was identified.</p>}
            {analysis.minimum_cut ? (
              <p className="muted">
                Remediation {analysis.minimum_cut.proven ? 'is a proven minimum cut' : 'is a heuristic, not a proven minimum cut'}: {(analysis.minimum_cut.edges || []).length} edge(s). {analysis.minimum_cut.reason || ''}
              </p>
            ) : null}
          </div>
        )}
      </div>

      <div className="card">
        <div className="sectionHeader"><h3>Limitations</h3></div>
        <div className="stack">
          {(body.limitations || []).map((item: string) => <p key={item} className="muted">{item}</p>)}
        </div>
      </div>
    </section>
  );
}
