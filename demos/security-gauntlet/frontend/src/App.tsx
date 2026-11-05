import { useEffect, useState } from 'react';
import { AuthorityGraph } from './AuthorityGraph';
import { scopeLines, type Leg, type ScenarioCard, type ScenarioRecord, type Verdict } from './types';

const STEPS = [
  'Legitimate task',
  'Hazardous path',
  'Baseline',
  'Control',
  'Protected execution',
  'Observed difference',
  'Evidence',
];

function tone(verdict: Verdict | undefined): string {
  return verdict || 'INCONCLUSIVE';
}

function claimLeg(record: ScenarioRecord): Leg | undefined {
  const name = record.outcomes.overall.claim_leg;
  return [...record.legs, ...(record.comparison || [])].find((leg) => leg.name === name);
}

export function App() {
  const [cards, setCards] = useState<ScenarioCard[]>([]);
  const [selected, setSelected] = useState('predictive-authority');
  const [record, setRecord] = useState<ScenarioRecord | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [checkout, setCheckout] = useState('');
  const [step, setStep] = useState(0);

  useEffect(() => {
    fetch('/api/scenarios')
      .then((response) => response.json())
      .then((body: { scenarios: ScenarioCard[] }) => {
        setCards(body.scenarios);
        setSelected((current) => (body.scenarios.some((item) => item.id === current) ? current : body.scenarios[0]?.id || current));
      })
      .catch(() => setError('The gauntlet API is not reachable.'));
    fetch('/api/capabilities')
      .then((response) => response.json())
      .then((body: { checkout?: string; version?: string; os_enforcement_in_this_tree?: boolean }) => {
        setCheckout(`${body.version || 'unknown'} · ${body.checkout || 'unknown'} · OS enforcement in this tree: ${body.os_enforcement_in_this_tree ? 'yes' : 'no'}`);
      })
      .catch(() => undefined);
  }, []);

  async function run() {
    setBusy(true);
    setError('');
    setStep(0);
    try {
      const response = await fetch(`/api/scenarios/${selected}/run`, { method: 'POST' });
      if (!response.ok) {
        throw new Error(`run failed (${response.status})`);
      }
      setRecord(await response.json() as ScenarioRecord);
    } catch (exc) {
      setRecord(null);
      setError(exc instanceof Error ? exc.message : 'run failed');
    } finally {
      setBusy(false);
    }
  }

  const lines = record ? scopeLines(record) : null;
  const claim = record ? claimLeg(record) : undefined;
  const card = cards.find((item) => item.id === selected);

  return (
    <main>
      <header>
        <h1>Varden security gauntlet</h1>
        <p>
          One run executes the baseline and the protected workflow against the Varden control plane.
          The three verdicts below are the same strings as the JSON and HTML exports.
        </p>
        <p className="mono muted">{checkout}</p>
      </header>
      <div className="layout">
        <nav className="nav" aria-label="Scenarios">
          {cards.map((item) => (
            <button key={item.id} aria-pressed={item.id === selected} onClick={() => { setSelected(item.id); setRecord(null); setStep(0); }}>
              {item.title}
            </button>
          ))}
          <button onClick={run} disabled={busy}>{busy ? 'Running' : 'Execute baseline and protected run'}</button>
        </nav>
        <section className="panel">
          {error ? <p className="verdict" data-kind="EXECUTION_ERROR">{error}</p> : null}
          <p className="muted">{card?.title || selected}. The page does not ship a stored success.</p>
          <ol className="steps">
            {STEPS.map((label, index) => (
              <li key={label}>
                <button aria-pressed={step === index} disabled={!record && index > 1} onClick={() => setStep(index)}>{index + 1}. {label}</button>
              </li>
            ))}
          </ol>
          {record && lines ? (
            <div className="scopes" aria-label="Scoped verdicts">
              <p className="verdict" data-kind={tone(record.outcomes.baseline.verdict)}>{lines.baseline}</p>
              <p className="verdict" data-kind={tone(record.outcomes.protected.verdict)}>{lines.protected}</p>
              <p className="verdict" data-kind={tone(record.outcomes.overall.verdict)}>{lines.overall}</p>
              <p className="muted">{record.outcomes.overall.basis}</p>
            </div>
          ) : null}
          {step === 0 ? <p><strong>Legitimate task. </strong>{record?.guide?.legitimate_task || record?.objective || 'Run the scenario to record the task that was actually sent.'}</p> : null}
          {step === 1 ? (
            <>
              <p><strong>Hazardous path. </strong>{record?.guide?.hazard || record?.untrusted_content || 'Run the scenario. The path is taken from that execution, not from a fixture.'}</p>
              {record?.scenario_id === 'predictive-authority' ? <AuthorityGraph graph={record.predictive?.graph} /> : null}
            </>
          ) : null}
          {step === 2 ? <LegList title="Baseline" legs={record?.comparison || []} empty="Run the scenario to record the unprotected execution." /> : null}
          {step === 3 ? <p><strong>Control. </strong>{record?.guide?.control_name || record?.enforcement_mode || 'The control is named by the run.'}</p> : null}
          {step === 4 ? <LegList title="Protected execution" legs={record?.legs || []} empty="Run the scenario to record the protected execution." /> : null}
          {step === 5 ? <p><strong>Observed difference. </strong>{record?.guide?.difference || 'The difference is the baseline verdict beside the protected verdict.'}</p> : null}
          {step === 6 && record ? <Evidence record={record} claim={claim} /> : null}
          {step === 6 && !record ? <p className="muted">Evidence appears after a run.</p> : null}
        </section>
      </div>
    </main>
  );
}

function LegList({ title, legs, empty }: { title: string; legs: Leg[]; empty: string }) {
  return (
    <div>
      <h2>{title}</h2>
      {legs.length === 0 ? <p className="muted">{empty}</p> : (
        <ol>
          {legs.map((leg) => (
            <li key={leg.leg_id || leg.name}>
              <span className="mono">{leg.scope} · {leg.verdict}</span> {leg.name}
              <div className="muted">{leg.decision || 'no decision'} · {leg.control_layer}</div>
              <div className="muted">{leg.detail}</div>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

function Evidence({ record, claim }: { record: ScenarioRecord; claim: Leg | undefined }) {
  const guard = claim?.guard;
  return (
    <div>
      <h2>Evidence</h2>
      <dl className="evidence">
        <dt>Run</dt><dd className="mono">{record.run_id}</dd>
        <dt>Claim leg</dt><dd className="mono">{claim?.leg_id || 'none'}</dd>
        <dt>Varden</dt><dd className="mono">{record.varden_version} · {record.commit}</dd>
        <dt>Platform</dt><dd className="mono">{record.platform}</dd>
        <dt>Enforcement mechanism</dt><dd className="mono">{record.enforcement_mode}{claim?.mechanism ? ` · ${claim.mechanism}` : ''}</dd>
        <dt>Guard decision</dt><dd className="mono">{guard?.decision || 'no guard response on the claim leg'}</dd>
        <dt>Guard reason</dt><dd>{guard?.reason || 'The claim leg did not call /sdk/guard.'}</dd>
        <dt>Event</dt><dd className="mono">{guard?.event_id ?? 'none'}</dd>
        <dt>HTTP</dt><dd className="mono">{guard?.http_status ?? 'none'}</dd>
        <dt>Before</dt><dd className="mono">{claim?.before_sha256 || 'none'}</dd>
        <dt>After</dt><dd className="mono">{claim?.after_sha256 || 'none'}</dd>
        <dt>Predictive decision</dt><dd className="mono">{record.predictive?.intervention?.decision || 'not this scenario'}</dd>
      </dl>
      {record.scenario_id === 'predictive-authority' ? <AuthorityGraph graph={record.predictive?.graph} /> : null}
      <p>
        <a href={`/api/runs/${record.run_id}/evidence.json`}>JSON</a>
        {' · '}
        <a href={`/api/runs/${record.run_id}/report.html`}>HTML assessment</a>
      </p>
      <h2>Coverage</h2>
      <ul>{record.coverage_limitations.map((item) => <li key={item}>{item}</li>)}</ul>
      {record.operator_change ? <p><strong>What changes enforcement. </strong>{record.operator_change}</p> : null}
      <h2>Simulated</h2>
      <ul>{record.simulated.map((item) => <li key={item}>{item}</li>)}</ul>
      <h2>Platform</h2>
      <pre className="mono">{JSON.stringify(record.platform_status, null, 2)}</pre>
    </div>
  );
}
