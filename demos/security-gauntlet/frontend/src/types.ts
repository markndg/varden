export type Verdict =
  | 'VERIFIED_PREVENTED'
  | 'VERIFIED_ALLOWED'
  | 'OBSERVED_ONLY'
  | 'INCONCLUSIVE'
  | 'UNSUPPORTED'
  | 'EXECUTION_ERROR';

export interface GuardExcerpt {
  http_status?: number;
  event_id?: string | number | null;
  decision?: string;
  reason?: string;
  matched_rule?: unknown;
  classifiers?: Record<string, boolean>;
  predictive_authority?: Record<string, unknown> | null;
}

export interface Leg {
  name: string;
  leg_id?: string;
  scope?: 'baseline' | 'protected' | 'overall';
  verdict: Verdict;
  decision: string;
  control_layer: string;
  attempted: boolean;
  completed: boolean;
  before_sha256: string | null;
  after_sha256: string | null;
  detail: string;
  guard?: GuardExcerpt | null;
  mechanism?: string;
}

export interface ScopeOutcome {
  scope: 'baseline' | 'protected' | 'overall';
  verdict: Verdict;
  legs: string[];
  claim_leg?: string;
  basis?: string;
  excludes_baseline?: boolean;
}

export interface GraphNode {
  id?: string;
  node_id?: string;
  label?: string;
  node_type?: string;
  lifecycle?: string;
  state?: string;
  confirmed?: boolean;
}

export interface GraphEdge {
  id?: string;
  src?: string;
  dst?: string;
  source?: string;
  target?: string;
  kind?: string;
  label?: string;
}

export interface AuthorityGraph {
  present?: boolean;
  trace_id?: string;
  session_key?: string;
  analysis_incomplete?: boolean;
  incompleteness_reason?: string | null;
  hazard_node_ids?: string[];
  capabilities?: string[];
  findings?: { pattern?: string; description?: string; path?: { nodes?: string[]; display?: string } }[];
  graph?: { nodes?: GraphNode[]; edges?: GraphEdge[] };
  note?: string;
}

export interface ScenarioRecord {
  scenario_id: string;
  title: string;
  business_impact: string;
  objective: string;
  run_id: string;
  varden_version: string;
  commit: string;
  platform: string;
  enforcement_mode: string;
  verdict: Verdict;
  outcomes: {
    baseline: ScopeOutcome;
    protected: ScopeOutcome;
    overall: ScopeOutcome;
  };
  user_intent?: string;
  untrusted_content?: string;
  operator_change?: string;
  legs: Leg[];
  comparison?: Leg[];
  timeline: { step: string; scope?: string; verdict: Verdict; decision: string; detail: string; leg_id?: string }[];
  predictive?: {
    default_product_state?: string;
    intervention?: { leg?: string; decision?: string; reason?: string; event_id?: string | number | null } | null;
    graph?: AuthorityGraph;
    residual_capabilities?: string[];
    with_pa_external_post?: string;
    without_pa_external_post?: string;
  } | null;
  guide?: {
    legitimate_task?: string;
    hazard?: string;
    control_name?: string;
    difference?: string;
  };
  platform_status?: Record<string, unknown>;
  coverage_limitations: string[];
  simulated: string[];
  side_effect_completed?: boolean;
  assurance?: {
    sdk?: { verdict: Verdict; leg: string };
    os_supervised?: { verdict: Verdict; leg: string; mechanism?: string };
    unsupervised_same_user?: { verdict: Verdict; leg: string };
  };
  production_entry?: {
    entry_point?: string;
    cases?: { name: string; outcome: string; capability?: string }[];
  };
  authority?: {
    isolated?: { status?: string };
    developer?: { status?: string };
  };
}

export interface ScenarioCard {
  id: string;
  title: string;
}

export function scopeLines(record: Pick<ScenarioRecord, 'outcomes'>): { baseline: string; protected: string; overall: string } {
  const claim = record.outcomes.protected.claim_leg;
  const named = claim && record.outcomes.protected.legs.includes(claim);
  const protectedLabel = named ? `Protected execution (${claim})` : 'Protected execution';
  return {
    baseline: `Baseline execution: ${record.outcomes.baseline.verdict}`,
    protected: `${protectedLabel}: ${record.outcomes.protected.verdict}`,
    overall: `Overall scenario outcome: ${record.outcomes.overall.verdict}`,
  };
}

const ASSURANCE_LABELS = {
  sdk: 'SDK-mediated protection',
  os_supervised: 'OS-supervised process',
  unsupervised_same_user: 'Unsupervised same-user process',
} as const;

export function assuranceLines(assurance: ScenarioRecord['assurance']): string[] {
  if (!assurance) {
    return [];
  }
  return (Object.keys(ASSURANCE_LABELS) as (keyof typeof ASSURANCE_LABELS)[])
    .filter((key) => assurance[key]?.verdict)
    .map((key) => `${ASSURANCE_LABELS[key]}: ${assurance[key]?.verdict}`);
}
