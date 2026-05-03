import React from 'react';
import { TraceGraph } from './TraceGraph';
import { CodeCard, KeyValue } from '../ui/Cards';

type DecisionPageProps = {
  detail: any;
  onOpenDecision: (id: number) => void;
  onOpenRule: (label: string, bucket?: string, token?: string) => void;
  helpers: {
    statusTone: (status: string) => string;
    eventOutcomeStatus: (event: any) => string;
    fmtTs: (ts?: number) => string;
    deriveMatchedRuleLabel: (event: any) => string | null;
    summarizeRiskReasonLabels: (reasons: string[]) => string | null;
    eventRoleTone: (explainability: any) => string;
    eventRoleDescription: (explainability: any) => string;
    displayValue: (value: any) => string;
    eventRuleBucket: (event: any) => string;
    semanticRuleFingerprint: (rule: any) => string;
    formatRuleFieldLabel: (field?: string | null) => string;
    describeMatchedField: (row: any) => string;
    compactValue: (value: any) => string;
    summarizeMatchedFields: (rows: any[], max?: number) => string | null;
    deriveRuleLabelFromRuleObject: (rule: any, fallbackStatus?: string) => string | null;
    normalizeEventRow: (event: any) => any;
    classNames: (...parts: Array<string | false | null | undefined>) => string;
  };
};

export function DecisionPage({ detail, onOpenDecision, onOpenRule, helpers }: DecisionPageProps) {
  const { statusTone, eventOutcomeStatus, fmtTs, deriveMatchedRuleLabel, summarizeRiskReasonLabels, eventRoleTone, eventRoleDescription, displayValue, eventRuleBucket, semanticRuleFingerprint, formatRuleFieldLabel, describeMatchedField, compactValue, summarizeMatchedFields, deriveRuleLabelFromRuleObject, normalizeEventRow, classNames } = helpers;
  const event = detail.event || {};
  const action = event.action || {};
  return (
    <div className="pageGrid">
      <section className="layout layout--twoThirds">
        <div className="stack">
          <div className="card">
            <div className="sectionHeader">
              <div>
                <div className="eyebrow">Decision details</div>
                <h3>{action.tool || action.type || 'event'} <span className={`badge badge--${statusTone(eventOutcomeStatus(event))}`}>{eventOutcomeStatus(event)}</span></h3>
              </div>
              <div className="toggleRow">
                {detail.neighbors?.previous_event_id ? <button className="button button--ghost" onClick={() => onOpenDecision(detail.neighbors.previous_event_id)}>Previous</button> : null}
                {detail.neighbors?.next_event_id ? <button className="button button--ghost" onClick={() => onOpenDecision(detail.neighbors.next_event_id)}>Next</button> : null}
              </div>
            </div>
            <div className="detailGrid">
              <KeyValue label="Timestamp" value={fmtTs(event.timestamp)} displayValue={displayValue} />
              <KeyValue label="Agent" value={action.agent_name} displayValue={displayValue} />
              <KeyValue label="Trace" value={event.trace_id} displayValue={displayValue} />
              <KeyValue label="Risk" value={`${detail.explainability?.risk_score ?? action.risk_score ?? 0}/100`} displayValue={displayValue} />
              <KeyValue label="Decision reason" value={detail.explainability?.reason || event.decision?.reason} displayValue={displayValue} />
              <KeyValue label="Triggered rule" value={detail.explainability?.rule_label || deriveMatchedRuleLabel(event)} displayValue={displayValue} />
              <KeyValue label="Step type" value={detail.explainability?.event_role_label || 'Recorded trace step'} displayValue={displayValue} />
              <KeyValue label="Route" value={event.decision?.route_target || action.route_target} displayValue={displayValue} />
              <KeyValue label="Scored because" value={detail.explainability?.score_summary || summarizeRiskReasonLabels(detail.explainability?.risk_reasons || []) || 'No scoring explanation recorded'} displayValue={displayValue} />
            </div>
            <div className="decisionNarrative">
              <div className={`decisionCallout decisionCallout--${eventRoleTone(detail.explainability)}`}>
                <strong>{detail.explainability?.event_role_label || 'Recorded trace step'}</strong>
                <span>{eventRoleDescription(detail.explainability)}</span>
              </div>
              <div className="subheading">Decision journey</div>
              <div className="journeyList">
                <div className="journeyStep"><span className="journeyStep__index">1</span><div><strong>{action.agent_name || 'Agent'}</strong><span>selected the <code>{action.tool || action.type || 'action'}</code> tool</span></div></div>
                <div className="journeyStep"><span className="journeyStep__index">2</span><div><strong>Sent payload</strong><span>{displayValue(event.input_payload || action.args || action.payload || 'No payload recorded')}</span></div></div>
                <div className="journeyStep"><span className="journeyStep__index">3</span><div><strong>Risk evaluation</strong><span>{detail.explainability?.score_summary || summarizeRiskReasonLabels(detail.explainability?.risk_reasons || []) || 'No scoring explanation recorded'}</span></div></div>
                <div className="journeyStep"><span className="journeyStep__index">4</span><div><strong>Triggered policy</strong><span><strong>{detail.explainability?.rule_label || deriveMatchedRuleLabel(event) || 'No explicit rule hit recorded'}</strong>{detail.explainability?.trigger_summary ? ` · ${detail.explainability?.trigger_summary}` : ''}</span></div></div>
                <div className="journeyStep journeyStep--decision"><span className="journeyStep__index">5</span><div><strong>Final decision</strong><span>{detail.explainability?.effective_action || event.status} · {detail.explainability?.reason || event.decision?.reason || 'No reason recorded'}{detail.explainability?.inherited_decision_context ? ' · context carried forward from earlier trace step' : ''}</span></div></div>
              </div>
              <div className="ruleJumpRow">
                {Array.from(new Set([detail.explainability?.rule_label, deriveMatchedRuleLabel(event), event?.decision?.rule_name, event?.decision?.triggered_rule].filter(Boolean) as string[])).map((label: string) => (
                  <button key={label} className="badge badge--rule badge--clickable" onClick={() => onOpenRule(label, eventRuleBucket(event), event?.decision?.matched_rule ? semanticRuleFingerprint(event.decision.matched_rule) : '')}>Open rule · {label}</button>
                ))}
              </div>
            </div>
            <div className="codeGrid">
              <CodeCard title="Action" value={action} displayValue={displayValue} />
              <CodeCard title="Input payload" value={event.input_payload} displayValue={displayValue} />
              <CodeCard title="Output payload" value={event.output_payload} displayValue={displayValue} />
              <div className="codeCard">
                <div className="subheading">Why this triggered</div>
                <div className="explainPanel">
                  <div className="explainPanel__headline">
                    <strong>{detail.explainability?.rule_label || deriveMatchedRuleLabel(event) || 'No explicit rule hit recorded'}</strong>
                    <span>{detail.explainability?.effective_action || event.status}</span>
                  </div>
                  <div className="explainPanel__summary">{detail.explainability?.trigger_summary || detail.explainability?.rule_match_summary || summarizeMatchedFields(detail.explainability?.matched_fields || [], 3) || detail.explainability?.reason || 'No specific rule-field explanation was captured for this event.'}</div>
                  <div className="explainPanel__summary"><strong>Risk score:</strong> {detail.explainability?.score_summary || 'No scoring explanation recorded.'}</div>
                  {detail.explainability?.inherited_decision_context ? <div className="explainPanel__note">This step appears to inherit a previous warn/block context rather than introducing new scored risk on its own.</div> : null}
                </div>
                <div className="chipGrid">
                  {(detail.explainability?.matched_fields || []).map((row: any, idx: number) => <div key={idx} className="chip"><strong>{formatRuleFieldLabel(row.field)}</strong><span>{describeMatchedField(row)}</span><code>{compactValue(row.actual)}</code></div>)}
                  {!(detail.explainability?.matched_fields || []).length ? <div className="muted">No rule-field explanation was captured for this event.</div> : null}
                </div>
                {(detail.explainability?.risk_reason_labels || []).length ? <div className="chipGrid">{(detail.explainability?.risk_reason_labels || []).map((label: string, idx: number) => <div key={`${label}-${idx}`} className="chip chip--reason"><strong>Score driver</strong><span>{label}</span></div>)}</div> : null}
              </div>
            </div>
          </div>
          <div className="card">
            <div className="sectionHeader">
              <div>
                <div className="eyebrow">Workflow context</div>
                <h3>Related events</h3>
              </div>
            </div>
            <div className="eventRail">
              {(detail.workflow_events || []).map((row: any) => (
                <button key={row.id} className="eventRow" onClick={() => onOpenDecision(row.id)}>
                  <div className={classNames('eventRow__dot', `is-${statusTone(eventOutcomeStatus(row))}`)} />
                  <div className="eventRow__main">
                    <div className="eventRow__title">{row.action?.tool || row.action?.type || 'event'}</div>
                    <div className="eventRow__meta">{row.action?.agent_name || 'unknown agent'} · {fmtTs(row.timestamp)}</div>
                  </div>
                  <div className="eventRow__score">{Math.round(row.action?.risk_score || 0)}</div>
                </button>
              ))}
            </div>
          </div>
        </div>
        <div className="stack">
          <div className="card">
            <div className="sectionHeader">
              <div>
                <div className="eyebrow">Trace graph</div>
                <h3>Flow around this decision</h3>
              </div>
            </div>
            <TraceGraph trace={detail.trace} onOpenDecision={onOpenDecision} onOpenRule={onOpenRule} compact helpers={{ eventOutcomeStatus, statusTone, deriveMatchedRuleLabel, deriveRuleLabelFromRuleObject, normalizeEventRow, eventRuleBucket, fmtTs, displayValue }} />
          </div>
        </div>
      </section>
    </div>
  );
}
