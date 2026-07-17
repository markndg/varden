export type EventRow = {
  id: number;
  timestamp: number;
  tool?: string;
  agent_name?: string;
  status: string;
  outcome?: string;
  decision_action?: string;
  effective_action?: string;
  risk_score?: number;
  route_target?: string;
  reason?: string;
  workflow_id?: string | null;
  domain?: string | null;
  classifiers?: Record<string, boolean>;
  trace_id?: string | null;
  decision_latency_ms?: number | null;
  /** Present when the source event row included full `action` (e.g. trace payloads). Used for client-side rule rollups. */
  action_type?: string;
  action_args?: Record<string, any> | any[] | null;
  action_metadata?: Record<string, any> | null;
  action_url?: string | null;
  matched_rule?: Record<string, any> | string | null;
};

export type TraceSummary = {
  trace_id: string;
  events: any[];
  graph: { nodes: any[]; edges: any[] };
  summary: {
    event_count: number;
    statuses: Record<string, number>;
    tools: Record<string, number>;
    agents: Record<string, number>;
    start_timestamp: number;
    end_timestamp: number;
  };
};

export type TraceOption = { trace_id: string; label: string };

export type DashboardPayload = {
  metrics: any;
  coverage: any;
  posture: string;
  timeline: any[];
  status_breakdown: Record<string, number>;
  route_breakdown: Record<string, number>;
  top_tools: Array<{ tool: string; count: number }>;
  top_agents: Array<{ agent: string; count: number }>;
  top_domains: Array<{ domain: string; count: number }>;
  http_methods: Array<{ method: string; count: number }>;
  risk_distribution: Record<string, number>;
  classifier_hits: Array<{ classifier: string; count: number }>;
  recent_events: EventRow[];
  recent_alerts: any[];
  latest_risk: any[];
  decision_latency_points: any[];
  scan_performance: any;
  insights: any[];
  recent_traces?: TraceSummary[];
  trace_catalogue?: TraceSummary[];
  alerts?: { items: any[] };
  workflows?: any[];
  jobs?: any[];
  policy_versions?: any[];
  config?: any;
  generated_at?: number;
};

export type EventDetail = {
  event: any;
  neighbors: { previous_event_id?: number | null; next_event_id?: number | null };
  workflow_events: any[];
  explainability: any;
  trace?: TraceSummary | null;
};

export type PolicyDoc = { block: any[]; warn: any[]; monitor: any[]; allow: any[]; budget_rules?: any[] };

export const RULE_BUCKETS = ['block', 'warn', 'monitor', 'allow'] as const;
export const BUDGET_RULES_BUCKET = 'budget_rules' as const;
export const POLICY_BUCKETS = [...RULE_BUCKETS, BUDGET_RULES_BUCKET] as const;
export const RULE_TYPES = ['', 'tool_call', 'http_request', 'llm_call'];
export const CLASSIFIER_KEYS = ['internal', 'secrets', 'pii', 'financial', 'credit_card', 'source_internal', 'unsafe_keywords'];
export const ADVANCED_FIELDS = [
  { key: 'field:url', label: 'URL contains', operator: 'contains', placeholder: 'api.example.com', valueType: 'text' },
  { key: 'field:domain', label: 'Domain contains', operator: 'contains', placeholder: 'internal.local', valueType: 'text' },
  { key: 'field:args.args', label: 'Command contains', operator: 'contains', placeholder: 'rm -rf', valueType: 'text' },
  { key: 'field:metadata.behavior.suspicious_sequence', label: 'Suspicious sequence', operator: 'eq', valueType: 'boolean' },
  { key: 'field:metadata.behavior.previous_blocked', label: 'Previous blocked in trace', operator: 'eq', valueType: 'boolean' },
];
export const OPERATOR_OPTIONS = ['eq', 'contains', 'startswith', 'endswith', 'exists', 'gte', 'lte', 'in'];
