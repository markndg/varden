export type Verdict =
  | 'VERIFIED_PREVENTED'
  | 'VERIFIED_ALLOWED'
  | 'OBSERVED_ONLY'
  | 'INCONCLUSIVE'
  | 'UNSUPPORTED'
  | 'EXECUTION_ERROR';

export interface Leg {
  name: string;
  verdict: Verdict;
  decision: string;
  control_layer: string;
  attempted: boolean;
  completed: boolean;
  before_sha256: string | null;
  after_sha256: string | null;
  detail: string;
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
  user_intent?: string;
  untrusted_content?: string;
  operator_change?: string;
  legs: Leg[];
  comparison?: Leg[];
  timeline: { step: string; verdict: Verdict; decision: string; detail: string }[];
  predictive?: Record<string, unknown> | null;
  coverage_limitations: string[];
  simulated: string[];
  side_effect_completed?: boolean;
}

export interface ScenarioCard {
  id: string;
  title: string;
}
