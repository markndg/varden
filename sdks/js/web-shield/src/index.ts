import type {
  ConnectionHealth,
  Finding,
  InvocationResult,
  OutputScanResult,
  RegisterToolOptions,
  RegistrationResult,
  RiskResult,
  WebMCPToolDefinitionInput,
  WebShieldConfig,
  WebShieldEventListener,
  WebShieldEventName,
} from './types.js';

export * from './types.js';

const SDK_VERSION = '0.1.0';

function randomId(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID();
  return `ws-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function currentOrigin(): string {
  if (typeof location !== 'undefined' && location.origin) return location.origin;
  return 'about:blank';
}

/** Best-effort structured clone; a hostile/unusual page object must never
 * throw out of the SDK. */
function safeSnapshot<T>(value: T): T {
  try {
    return JSON.parse(JSON.stringify(value));
  } catch {
    return value;
  }
}

export interface VardenWebShield {
  readonly sessionId: string;
  registerTool(
    modelContext: { registerTool: (tool: unknown) => unknown } | null | undefined,
    tool: WebMCPToolDefinitionInput,
    options?: RegisterToolOptions,
  ): Promise<RegistrationResult>;
  unregisterTool(identityKey: string): Promise<void>;
  evaluateInvocation(identityKey: string, args?: Record<string, unknown>): Promise<InvocationResult>;
  completeInvocation(identityKey: string, status: 'success' | 'error', latencyMs?: number, error?: string): Promise<void>;
  scanOutput(identityKey: string, outputText: string, opts?: { containsUserGeneratedContent?: boolean }): Promise<OutputScanResult>;
  health(): Promise<ConnectionHealth>;
  /** Wraps `document.modelContext.registerTool`/`navigator.modelContext.registerTool`
   * (when present in this environment) so a site can opt in once instead of
   * calling `registerTool()` explicitly for every tool. Safe to call more
   * than once; re-installing is a no-op. Returns an `uninstall()` function. */
  install(): () => void;
  on(event: WebShieldEventName, listener: WebShieldEventListener): () => void;
}

class VardenWebShieldImpl implements VardenWebShield {
  readonly sessionId: string;
  private readonly config: Required<Omit<WebShieldConfig, 'apiKey'>> & { apiKey?: string };
  private readonly fetchImpl: typeof fetch;
  private readonly listeners = new Map<WebShieldEventName, Set<WebShieldEventListener>>();
  private apiKeyPromise: Promise<string> | null = null;
  private lastConnected = true;

  constructor(config: WebShieldConfig) {
    if (!config.endpoint) throw new Error('createVardenWebShield: "endpoint" is required');
    this.config = {
      endpoint: config.endpoint.replace(/\/$/, ''),
      mode: config.mode ?? 'enforce',
      sessionId: config.sessionId ?? randomId(),
      fetchImpl: config.fetchImpl ?? fetch,
      timeoutMs: config.timeoutMs ?? 4000,
      extensionVersion: config.extensionVersion ?? '',
      apiKey: config.apiKey,
    };
    this.fetchImpl = this.config.fetchImpl;
    this.sessionId = this.config.sessionId;
  }

  on(event: WebShieldEventName, listener: WebShieldEventListener): () => void {
    if (!this.listeners.has(event)) this.listeners.set(event, new Set());
    this.listeners.get(event)!.add(listener);
    return () => this.listeners.get(event)?.delete(listener);
  }

  private emit(event: WebShieldEventName, payload: unknown) {
    this.listeners.get(event)?.forEach((listener) => {
      try {
        listener(payload);
      } catch {
        /* listener errors must never break the SDK */
      }
    });
  }

  private async apiKey(): Promise<string> {
    if (this.config.apiKey) return this.config.apiKey;
    if (!this.apiKeyPromise) {
      this.apiKeyPromise = this.fetchImpl(`${this.config.endpoint}/health`, { signal: this.timeoutSignal() })
        .then((res) => (res.ok ? res.json() : {}))
        .then((health: { bootstrap_api_key?: string }) => health.bootstrap_api_key ?? '')
        .catch(() => '');
    }
    return this.apiKeyPromise;
  }

  private timeoutSignal(): AbortSignal | undefined {
    if (typeof AbortSignal !== 'undefined' && 'timeout' in AbortSignal) {
      return (AbortSignal as any).timeout(this.config.timeoutMs);
    }
    return undefined;
  }

  private async post(path: string, body: Record<string, unknown>): Promise<{ status: number; data: any }> {
    const apiKey = await this.apiKey();
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.config.endpoint}${path}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(apiKey ? { 'x-api-key': apiKey } : {}),
        },
        body: JSON.stringify(body),
        signal: this.timeoutSignal(),
      });
    } catch (err) {
      this.setConnected(false);
      throw new VardenWebShieldError(`Could not reach Varden at ${this.config.endpoint}: ${(err as Error).message}`, 'network_error');
    }
    this.setConnected(true);
    const text = await res.text();
    let data: any = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { raw: text };
    }
    if (!res.ok && res.status !== 403) {
      throw new VardenWebShieldError(`Varden Web Shield request failed (${res.status})`, 'server_error', data);
    }
    return { status: res.status, data };
  }

  private setConnected(connected: boolean) {
    if (connected !== this.lastConnected) {
      this.lastConnected = connected;
      this.emit('connection-change', { connected });
    }
  }

  async registerTool(
    modelContext: { registerTool: (tool: unknown) => unknown } | null | undefined,
    tool: WebMCPToolDefinitionInput,
    options: RegisterToolOptions = {},
  ): Promise<RegistrationResult> {
    const ownerOrigin = options.ownerOrigin ?? currentOrigin();
    const { status, data } = await this.post('/webshield/registrations', {
      session_id: this.sessionId,
      owner_origin: ownerOrigin,
      top_origin: options.topOrigin ?? ownerOrigin,
      api_surface: options.apiSurface ?? 'document_model_context',
      tool: safeSnapshot(tool),
      is_third_party_frame: options.isThirdPartyFrame ?? false,
      script_source_origin: options.scriptSourceOrigin,
      tab_id: options.tabId,
      frame_id: options.frameId,
      sdk_version: SDK_VERSION,
      extension_version: this.config.extensionVersion || undefined,
    });
    const detail = status === 403 ? data.detail : data;
    const metadata = detail?.event?.action?.metadata ?? {};
    const decision: string = metadata.requested_enforcement ?? (status === 403 ? 'block' : 'allow');
    const blocked = this.config.mode === 'enforce' && decision === 'block';

    if (!blocked && modelContext && typeof modelContext.registerTool === 'function') {
      const toolToRegister = decision === 'sanitise' && detail?.sanitizer?.sanitized_tool ? detail.sanitizer.sanitized_tool : tool;
      modelContext.registerTool(toolToRegister);
    }

    const result: RegistrationResult = {
      identityKey: detail?.identity_key ?? '',
      risk: detail?.scan?.risk as RiskResult,
      findings: (detail?.scan?.findings ?? []) as Finding[],
      event: detail?.event,
      approval: detail?.approval,
      sanitizedTool: detail?.sanitizer?.sanitized_tool,
      blocked,
      raw: data,
    };
    this.emit('registration', result);
    return result;
  }

  async unregisterTool(identityKey: string): Promise<void> {
    await this.post('/webshield/lifecycle', { session_id: this.sessionId, event: 'unregister', identity_key: identityKey });
  }

  async evaluateInvocation(identityKey: string, args?: Record<string, unknown>): Promise<InvocationResult> {
    const { status, data } = await this.post('/webshield/invocations', {
      session_id: this.sessionId,
      identity_key: identityKey,
      phase: 'requested',
      args: args ? safeSnapshot(args) : undefined,
      sdk_version: SDK_VERSION,
    });
    const detail = status === 403 ? data.detail : data;
    const metadata = detail?.event?.action?.metadata ?? {};
    const decision: string = metadata.requested_enforcement ?? (status === 403 ? 'block' : 'allow');
    const result: InvocationResult = {
      riskScore: detail?.risk_score ?? 0,
      riskBand: detail?.risk_band ?? 'low',
      event: detail?.event,
      approval: detail?.approval,
      blocked: this.config.mode === 'enforce' && decision === 'block',
      raw: data,
    };
    this.emit('invocation', result);
    return result;
  }

  async completeInvocation(identityKey: string, status: 'success' | 'error', latencyMs?: number, error?: string): Promise<void> {
    await this.post('/webshield/invocations', {
      session_id: this.sessionId,
      identity_key: identityKey,
      phase: 'completed',
      status,
      latency_ms: latencyMs,
      error,
    });
  }

  async scanOutput(identityKey: string, outputText: string, opts: { containsUserGeneratedContent?: boolean } = {}): Promise<OutputScanResult> {
    const { status, data } = await this.post('/webshield/outputs', {
      session_id: this.sessionId,
      identity_key: identityKey,
      output_text: outputText,
      contains_user_generated_content: opts.containsUserGeneratedContent ?? false,
    });
    const detail = status === 403 ? data.detail : data;
    const result: OutputScanResult = {
      outcome: detail?.outcome ?? 'allow',
      risk: detail?.risk as RiskResult,
      findings: (detail?.findings ?? []) as Finding[],
      sanitizedOutputText: detail?.sanitized_output_text,
      blocked: this.config.mode === 'enforce' && detail?.outcome === 'block',
      raw: data,
    };
    this.emit('output', result);
    return result;
  }

  async health(): Promise<ConnectionHealth> {
    const start = Date.now();
    try {
      const res = await this.fetchImpl(`${this.config.endpoint}/health/live`, { signal: this.timeoutSignal() });
      const connected = res.ok;
      this.setConnected(connected);
      return { connected, endpoint: this.config.endpoint, latencyMs: Date.now() - start };
    } catch (err) {
      this.setConnected(false);
      return { connected: false, endpoint: this.config.endpoint, error: (err as Error).message };
    }
  }

  install(): () => void {
    const targets: Array<{ root: any; prop: 'modelContext' }> = [];
    if (typeof document !== 'undefined') targets.push({ root: document, prop: 'modelContext' });
    if (typeof navigator !== 'undefined') targets.push({ root: navigator, prop: 'modelContext' });

    const uninstallers: Array<() => void> = [];
    for (const { root, prop } of targets) {
      const target = root[prop];
      if (!target || typeof target.registerTool !== 'function' || target.registerTool.__vardenWrapped) continue;
      const original = target.registerTool.bind(target);
      const wrapped = (tool: WebMCPToolDefinitionInput, ...rest: unknown[]) => {
        this.registerTool({ registerTool: () => {} }, tool).catch(() => {});
        return original(tool, ...rest);
      };
      (wrapped as any).__vardenWrapped = true;
      target.registerTool = wrapped;
      uninstallers.push(() => {
        if (root[prop] === target) target.registerTool = original;
      });
    }
    return () => uninstallers.forEach((fn) => fn());
  }
}

export class VardenWebShieldError extends Error {
  readonly kind: 'network_error' | 'server_error';
  readonly detail?: unknown;
  constructor(message: string, kind: 'network_error' | 'server_error', detail?: unknown) {
    super(message);
    this.name = 'VardenWebShieldError';
    this.kind = kind;
    this.detail = detail;
  }
}

export function createVardenWebShield(config: WebShieldConfig): VardenWebShield {
  return new VardenWebShieldImpl(config);
}
