/**
 * Coverage-gap classification for observed actions.
 * Zero gaps is not proof that an installation is fully protected.
 */

export type CoverageKind = 'covered' | 'uncovered' | 'weak' | 'near';

export type CoverageEvent = {
  matched_label?: string | null;
  decision_action?: string | null;
  effective_action?: string | null;
  status?: string | null;
  surface_status?: string | null;
  provenance_missing?: boolean;
  risk_score?: number;
  type?: string;
  tool?: string;
  method?: string;
  domain?: string;
  agent?: string;
  classifiers?: Record<string, unknown>;
  risk_reasons?: string[];
};

const COMPLETE_ENFORCEMENT = new Set([
  'block',
  'blocked',
  'require_approval',
  'sanitise',
  'sanitize',
  'warn',
  'warned',
]);

export function classifyCoverage(event: CoverageEvent, nearestScore = 0): { kind: CoverageKind; why: string } {
  const surface = String(event.surface_status || '').toUpperCase();
  if (surface === 'NOT_ROUTED') {
    return {
      kind: 'uncovered',
      why: 'The applicable surface is NOT_ROUTED. The action was observed without an enforcement route.',
    };
  }
  if (surface === 'PARTIAL' || surface === 'OBSERVATIONAL') {
    return {
      kind: 'weak',
      why: `Surface coverage is ${surface}. Partial or observational instrumentation is not complete enforcement.`,
    };
  }
  if (surface === 'UNCOVERED' || surface === 'UNSUPPORTED') {
    return {
      kind: 'uncovered',
      why: `Surface coverage is ${surface}. That status is not complete enforcement.`,
    };
  }
  if (event.provenance_missing) {
    return {
      kind: 'uncovered',
      why: 'The action is missing provenance, so coverage cannot be attributed to a trace or session.',
    };
  }
  const decision = String(event.effective_action || event.decision_action || event.status || '').toLowerCase();
  if (event.matched_label && COMPLETE_ENFORCEMENT.has(decision)) {
    return { kind: 'covered', why: '' };
  }
  if (!event.matched_label) {
    if (nearestScore >= 46) {
      return { kind: 'near', why: 'No rule matched this action. A nearby rule shares some of its shape.' };
    }
    if (nearestScore >= 24 || Number(event.risk_score || 0) >= 55) {
      return { kind: 'weak', why: 'No applicable policy matched this action. Nearby rules are only a weak fit.' };
    }
    return { kind: 'uncovered', why: 'No applicable policy matched this observed action.' };
  }
  return {
    kind: 'weak',
    why: 'A rule matched, but the decision is not complete enforcement.',
  };
}

export function gapClusterKey(event: CoverageEvent, kind: CoverageKind) {
  const domain = event.domain ? String(event.domain).split('.').slice(-2).join('.') : '';
  const classifiers = Object.keys(event.classifiers || {})
    .filter((key) => event.classifiers?.[key])
    .sort()
    .join('|');
  const reasons = (event.risk_reasons || []).slice().sort().join('|');
  return [kind, event.type || '', event.tool || '', event.method || '', domain, classifiers, reasons].join('::');
}

export type EmptyReason =
  | 'telemetry_unavailable'
  | 'analysis_failed'
  | 'no_observed_events'
  | 'agent_without_observations'
  | 'window_excludes_events'
  | 'filters_exclude_gaps'
  | 'no_uncovered_events';

export function explainCoverageEmpty(input: {
  overviewLoaded: boolean;
  analysisFailed?: boolean;
  observedCount: number;
  windowCount: number;
  clusterCount: number;
  visibleCount: number;
  agentFilter?: string;
  agentObserved?: boolean;
}): { reason: EmptyReason; title: string; detail: string } {
  if (!input.overviewLoaded) {
    return {
      reason: 'telemetry_unavailable',
      title: 'Coverage telemetry is unavailable',
      detail: 'The dashboard has not loaded observed events. This page cannot judge coverage until that telemetry arrives.',
    };
  }
  if (input.analysisFailed) {
    return {
      reason: 'analysis_failed',
      title: 'Gap analysis failed',
      detail: 'Observed events could not be classified. The empty list is not a coverage result.',
    };
  }
  if (input.observedCount <= 0) {
    return {
      reason: 'no_observed_events',
      title: 'No observed events',
      detail: 'Gap analysis has nothing to classify. Zero uncovered events is not proof of complete security coverage.',
    };
  }
  if (input.agentFilter && input.agentFilter !== 'all' && input.agentObserved === false) {
    return {
      reason: 'agent_without_observations',
      title: 'This agent has no observations',
      detail: `${input.agentFilter} has no events in the loaded telemetry. Absence of observations is not evidence that the agent is covered.`,
    };
  }
  if (input.windowCount <= 0) {
    return {
      reason: 'window_excludes_events',
      title: 'No events in this time window',
      detail: 'Older observations exist outside the selected window. Widen the window before treating the page as clear.',
    };
  }
  if (input.clusterCount > 0 && input.visibleCount <= 0) {
    return {
      reason: 'filters_exclude_gaps',
      title: 'Filters are hiding gap records',
      detail: `${input.clusterCount} gap cluster${input.clusterCount === 1 ? '' : 's'} match the loaded events, but the current filters exclude them.`,
    };
  }
  return {
    reason: 'no_uncovered_events',
    title: 'No uncovered events in this view',
    detail: 'Actions in this window have complete enforcement. Unobserved surfaces, partial routes, and events outside the window are not included in that result.',
  };
}
