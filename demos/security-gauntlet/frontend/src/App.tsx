import { useEffect, useState } from 'react';
import type { ScenarioCard, ScenarioRecord, Verdict } from './types';

function tone(verdict: Verdict | undefined): string {
  return verdict || 'INCONCLUSIVE';
}

export function App() {
  const [cards, setCards] = useState<ScenarioCard[]>([]);
  const [selected, setSelected] = useState('prompt-injection');
  const [record, setRecord] = useState<ScenarioRecord | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [checkout, setCheckout] = useState('');

  useEffect(() => {
    fetch('/api/scenarios')
      .then((response) => response.json())
      .then((body: { scenarios: ScenarioCard[] }) => setCards(body.scenarios))
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

  const comparison = record?.comparison || [];
  const protectedLegs = (record?.legs || []).filter((leg) => !leg.name.startsWith('without_pa'));

  return (
    <main>
      <header>
        <h1>Varden security gauntlet</h1>
        <p>
          Each run calls the Varden control plane in a disposable database and checks the resulting file.
          A policy sentence is not treated as proof that a write was stopped.
        </p>
        <p className="mono muted">{checkout}</p>
      </header>
      <div className="layout">
        <nav className="nav" aria-label="Scenarios">
          {cards.map((card) => (
            <button key={card.id} aria-pressed={card.id === selected} onClick={() => { setSelected(card.id); setRecord(null); }}>
              {card.title}
            </button>
          ))}
          <button onClick={run} disabled={busy}>{busy ? 'Running' : 'Run scenario'}</button>
        </nav>
        <section className="panel">
          {error ? <p className="verdict" data-kind="EXECUTION_ERROR">{error}</p> : null}
          {!record ? <p className="muted">Choose a scenario and run it. This screen does not ship a stored success.</p> : null}
          {record ? (
            <>
              <p className="verdict" data-kind={tone(record.verdict)}>{record.verdict}</p>
              <h2>{record.title}</h2>
              <p>{record.business_impact}</p>
              <p><strong>Objective. </strong>{record.objective}</p>
              {record.user_intent ? <p><strong>User intent. </strong>{record.user_intent}</p> : null}
              {record.untrusted_content ? <p><strong>Untrusted content. </strong>{record.untrusted_content}</p> : null}
              <p className="mono muted">{record.enforcement_mode} · {record.platform}</p>
              <div className="split">
                <div>
                  <h2>Varden execution</h2>
                  <ol>
                    {protectedLegs.map((leg) => (
                      <li key={leg.name}>
                        <span className="mono">{leg.verdict}</span> {leg.name}
                        <div className="muted">{leg.decision || 'no decision'} · {leg.control_layer}</div>
                        <div className="muted">{leg.detail}</div>
                      </li>
                    ))}
                  </ol>
                </div>
                <div>
                  <h2>Baseline</h2>
                  {comparison.length === 0 ? <p className="muted">This scenario has no separate baseline leg.</p> : (
                    <ol>
                      {comparison.map((leg) => (
                        <li key={leg.name}>
                          <span className="mono">{leg.verdict}</span> {leg.name}
                          <div className="muted">{leg.detail}</div>
                        </li>
                      ))}
                    </ol>
                  )}
                </div>
              </div>
              <h2>Timeline</h2>
              <ol>
                {record.timeline.map((step) => (
                  <li key={step.step}><span className="mono">{step.verdict}</span> {step.step} — {step.detail}</li>
                ))}
              </ol>
              <h2>Evidence</h2>
              <p className="mono">{record.run_id}</p>
              <p>
                <a href={`/api/runs/${record.run_id}/evidence.json`}>JSON</a>
                {' · '}
                <a href={`/api/runs/${record.run_id}/report.html`}>HTML assessment</a>
              </p>
              <h2>Coverage</h2>
              <ul>
                {record.coverage_limitations.map((item) => <li key={item}>{item}</li>)}
              </ul>
              {record.operator_change ? <p><strong>What changes enforcement. </strong>{record.operator_change}</p> : null}
              <h2>Simulated</h2>
              <ul>
                {record.simulated.map((item) => <li key={item}>{item}</li>)}
              </ul>
            </>
          ) : null}
        </section>
      </div>
    </main>
  );
}
