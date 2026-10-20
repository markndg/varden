import { describe, expect, it } from 'vitest';
import { classifyCoverage, explainCoverageEmpty, gapClusterKey } from './coverageGaps';

const base = {
  type: 'tool_call',
  tool: 'shell.exec',
  method: 'run',
  domain: '',
  agent: 'worker',
  classifiers: {},
  risk_reasons: [] as string[],
  risk_score: 10,
};

describe('coverage gap classification', () => {
  it('treats an observed action with no applicable policy as uncovered', () => {
    const result = classifyCoverage({ ...base, matched_label: null, status: 'allowed' }, 0);
    expect(result.kind).toBe('uncovered');
    expect(result.why).toMatch(/No applicable policy/i);
  });

  it('treats a PARTIAL surface as incomplete coverage', () => {
    const result = classifyCoverage({ ...base, surface_status: 'PARTIAL', matched_label: 'block shell', status: 'blocked' });
    expect(result.kind).toBe('weak');
    expect(result.why).toMatch(/PARTIAL/);
  });

  it('treats NOT_ROUTED on an applicable surface as uncovered', () => {
    const result = classifyCoverage({ ...base, surface_status: 'NOT_ROUTED', matched_label: 'monitor shell', status: 'monitor' });
    expect(result.kind).toBe('uncovered');
    expect(result.why).toMatch(/NOT_ROUTED/);
  });

  it('treats complete enforcement as covered', () => {
    const result = classifyCoverage({ ...base, matched_label: 'block shell', effective_action: 'block', provenance_missing: false });
    expect(result.kind).toBe('covered');
  });

  it('treats missing provenance as a gap even when a rule matched', () => {
    const result = classifyCoverage({
      ...base,
      matched_label: 'block shell',
      effective_action: 'block',
      provenance_missing: true,
    });
    expect(result.kind).toBe('uncovered');
    expect(result.why).toMatch(/provenance/i);
  });

  it('puts repeated observations of the same action in one cluster', () => {
    const first = gapClusterKey({ ...base, tool: 'sql.query' }, 'uncovered');
    const second = gapClusterKey({ ...base, tool: 'sql.query', agent: 'other' }, 'uncovered');
    expect(first).toBe(second);
  });

  it('explains an agent with no observations', () => {
    const view = explainCoverageEmpty({
      overviewLoaded: true,
      observedCount: 4,
      windowCount: 4,
      clusterCount: 1,
      visibleCount: 0,
      agentFilter: 'quiet-agent',
      agentObserved: false,
    });
    expect(view.reason).toBe('agent_without_observations');
    expect(view.detail).toMatch(/quiet-agent/);
  });

  it('explains filters that exclude otherwise valid gaps', () => {
    const view = explainCoverageEmpty({
      overviewLoaded: true,
      observedCount: 3,
      windowCount: 3,
      clusterCount: 2,
      visibleCount: 0,
      agentFilter: 'all',
      agentObserved: true,
    });
    expect(view.reason).toBe('filters_exclude_gaps');
  });

  it('does not describe zero events as complete coverage', () => {
    const view = explainCoverageEmpty({
      overviewLoaded: true,
      observedCount: 0,
      windowCount: 0,
      clusterCount: 0,
      visibleCount: 0,
    });
    expect(view.reason).toBe('no_observed_events');
    expect(view.detail).toMatch(/not proof/i);
  });
});
