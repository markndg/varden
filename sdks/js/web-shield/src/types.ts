export type ProtectionMode = 'observe' | 'enforce';

export interface WebShieldConfig {
  /** Base URL of the Varden server, e.g. "http://127.0.0.1:8000". */
  endpoint: string;
  /** API key with at least "ingest" scope. If omitted, the SDK will try to
   * auto-discover a dev bootstrap key from `${endpoint}/health` (only ever
   * present when the server is running with no operator-issued keys yet). */
  apiKey?: string;
  /** "observe" never blocks a registration/invocation/output locally, even
   * if the server's policy decision is "block" — it only reports. "enforce"
   * (the default) respects the server's decision. Risk scoring and the
   * server-recorded policy decision are identical either way; this only
   * changes what the SDK itself does with the result. */
  mode?: ProtectionMode;
  /** Reused across calls for lifecycle correlation. Auto-generated if omitted. */
  sessionId?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  extensionVersion?: string;
}

export interface WebMCPToolDefinitionInput {
  name: string;
  title?: string;
  description: string;
  inputSchema?: Record<string, unknown>;
  annotations?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface RegisterToolOptions {
  ownerOrigin?: string;
  topOrigin?: string;
  apiSurface?: 'document_model_context' | 'navigator_model_context' | 'declarative' | string;
  isThirdPartyFrame?: boolean;
  scriptSourceOrigin?: string;
  tabId?: string;
  frameId?: string;
}

export interface RiskDriver {
  rule_id: string;
  contribution: number;
  reason: string;
}

export interface Finding {
  rule_id: string;
  category: string;
  severity: string;
  field_path: string;
  evidence: string;
  explanation: string;
  confidence: number;
  remediation: string;
}

export interface RiskResult {
  score: number;
  band: 'low' | 'guarded' | 'suspicious' | 'high' | 'critical';
  profile_version: string;
  drivers: RiskDriver[];
}

export interface EnforcementMetadata {
  policy_decision?: string;
  requested_enforcement?: string;
  achieved_enforcement?: string;
  enforcement_limitation?: string | null;
  risk_band?: string;
  risk_score?: number;
  findings?: Finding[];
}

export interface WebShieldEvent {
  action: { type: string; metadata: EnforcementMetadata; [key: string]: unknown };
  [key: string]: unknown;
}

export interface RegistrationResult {
  identityKey: string;
  risk: RiskResult;
  findings: Finding[];
  event: WebShieldEvent;
  approval?: Record<string, unknown>;
  sanitizedTool?: WebMCPToolDefinitionInput;
  /** True when the SDK itself withheld the registration from the page's
   * modelContext because the server's decision was "block" and mode is
   * "enforce". */
  blocked: boolean;
  raw: unknown;
}

export interface InvocationResult {
  riskScore: number;
  riskBand: string;
  event: WebShieldEvent;
  approval?: Record<string, unknown>;
  blocked: boolean;
  raw: unknown;
}

export interface OutputScanResult {
  outcome: 'allow' | 'sanitise' | 'truncate' | 'quarantine' | 'block' | string;
  risk: RiskResult;
  findings: Finding[];
  sanitizedOutputText?: string;
  blocked: boolean;
  raw: unknown;
}

export interface ConnectionHealth {
  connected: boolean;
  endpoint: string;
  latencyMs?: number;
  error?: string;
}

export type WebShieldEventName = 'registration' | 'invocation' | 'output' | 'connection-change';

export type WebShieldEventListener = (payload: unknown) => void;
