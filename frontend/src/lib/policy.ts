import { PolicyDoc, RULE_BUCKETS, BUDGET_RULES_BUCKET } from './types';

function formatRuleFieldLabel(field?: string | null) {
  if (!field) return 'condition';
  if (field.startsWith('classifier:')) return `classifier ${field.split(':', 2)[1].replace(/_/g, ' ')}`;
  const normalized = field.startsWith('field:') ? field.slice(6) : field;
  return normalized.replace(/\./g, ' → ').replace(/_/g, ' ');
}

function compactValue(value: any) {
  if (value === undefined || value === null || value === '') return '—';
  if (typeof value === 'string') return value.length > 56 ? `${value.slice(0, 53)}…` : value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.slice(0, 3).map((item) => compactValue(item)).join(', ') + (value.length > 3 ? '…' : '');
  if (typeof value === 'object') {
    const entries = Object.entries(value).slice(0, 3).map(([key, entryValue]) => `${key}=${compactValue(entryValue)}`);
    return entries.join(', ');
  }
  return String(value);
}

function describeMatchedField(row: any): string {
  const field = formatRuleFieldLabel(row?.field);
  const operator = row?.operator;
  if (operator === 'contains') return `${field} contains ${compactValue(row?.expected)}`;
  if (operator === 'in') return `${field} matches ${compactValue(row?.expected)}`;
  if (operator === 'gte') return `${field} ≥ ${compactValue(row?.expected)} (actual ${compactValue(row?.actual)})`;
  if (operator === 'lte') return `${field} ≤ ${compactValue(row?.expected)} (actual ${compactValue(row?.actual)})`;
  if (operator === 'exists') return `${field} ${row?.expected ? 'exists' : 'is absent'}`;
  return `${field} is ${compactValue(row?.expected)}`;
}

export function ensurePolicyDoc(doc: any): PolicyDoc {
  return {
    block: Array.isArray(doc?.block) ? doc.block : [],
    warn: Array.isArray(doc?.warn) ? doc.warn : [],
    monitor: Array.isArray(doc?.monitor) ? doc.monitor : [],
    allow: Array.isArray(doc?.allow) ? doc.allow : [],
    budget_rules: Array.isArray(doc?.budget_rules) ? doc.budget_rules : [],
  };
}

export function stableStringify(value: any): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  const entries = Object.entries(value).sort(([left], [right]) => left.localeCompare(right));
  return `{${entries.map(([key, entryValue]) => `${JSON.stringify(key)}:${stableStringify(entryValue)}`).join(',')}}`;
}

export function ruleFingerprint(rule: any): string {
  return stableStringify(rule || {});
}

export function dedupeRules(rules: any[]) {
  const seen = new Set<string>();
  const out: any[] = [];
  for (const rule of rules || []) {
    const fingerprint = ruleFingerprint(rule);
    if (seen.has(fingerprint)) continue;
    seen.add(fingerprint);
    out.push(rule);
  }
  return out;
}

export function dedupePolicyDoc(doc: PolicyDoc): PolicyDoc {
  return {
    block: dedupeRules(doc.block),
    warn: dedupeRules(doc.warn),
    monitor: dedupeRules(doc.monitor),
    allow: dedupeRules(doc.allow),
    budget_rules: dedupeRules(doc.budget_rules || []),
  };
}

export function mergePolicyWithoutDuplicates(baseDoc: PolicyDoc, templateDoc: PolicyDoc): PolicyDoc {
  return dedupePolicyDoc({
    block: [...baseDoc.block, ...templateDoc.block],
    warn: [...baseDoc.warn, ...templateDoc.warn],
    monitor: [...baseDoc.monitor, ...templateDoc.monitor],
    allow: [...baseDoc.allow, ...templateDoc.allow],
    budget_rules: [...(baseDoc.budget_rules || []), ...(templateDoc.budget_rules || [])],
  });
}

export function isBudgetRulesBucket(bucket: string) {
  return bucket === BUDGET_RULES_BUCKET;
}

export function getBucketRules(doc: PolicyDoc, bucket: string): any[] {
  if (isBudgetRulesBucket(bucket)) return doc.budget_rules || [];
  return (doc as any)[bucket] || [];
}

export function withBucketRules(doc: PolicyDoc, bucket: string, rules: any[]): PolicyDoc {
  if (isBudgetRulesBucket(bucket)) return { ...doc, budget_rules: rules };
  return { ...doc, [bucket]: rules };
}

export function summarizeBudgetRule(rule: any) {
  if (!rule) return 'New token budget';
  const label = rule.title || rule.id || 'token budget';
  const limit = Number(rule.limit_usd ?? 0);
  const window = rule.window || 'session';
  const cap = rule.hard_cap === false ? 'soft cap' : 'hard cap';
  return `${label} · $${limit.toFixed(2)} / ${window} · ${cap}`;
}

export function pickFirstNonEmptyBucket(doc: PolicyDoc): typeof RULE_BUCKETS[number] | typeof BUDGET_RULES_BUCKET {
  const budget = (doc.budget_rules || []).length;
  if (budget > 0) return BUDGET_RULES_BUCKET;
  return RULE_BUCKETS.find((bucket) => (doc[bucket] || []).length > 0) || 'block';
}

export function safeParsePolicy(text: string, fallback: PolicyDoc) {
  try {
    return ensurePolicyDoc(JSON.parse(text));
  } catch {
    return fallback;
  }
}

export function setRuleSimpleValue(rule: any, key: string, value: any) {
  const next = { ...rule };
  if (value === '' || value === undefined || value === null) delete next[key];
  else next[key] = value;
  return next;
}

export function setRuleOperatorValue(rule: any, key: string, operator: string, rawValue: any) {
  const next = { ...rule };
  const empty = rawValue === '' || rawValue === undefined || rawValue === null;
  if (empty) {
    delete next[key];
    return next;
  }
  if (operator === 'eq' && typeof rawValue !== 'object') next[key] = rawValue;
  else next[key] = { [operator]: rawValue };
  return next;
}

export function getRuleOperator(rule: any, key: string, fallback = 'eq') {
  const value = rule?.[key];
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const operator = Object.keys(value)[0];
    return operator || fallback;
  }
  return fallback;
}

export function getRuleValue(rule: any, key: string) {
  const value = rule?.[key];
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const first = Object.keys(value)[0];
    return first ? (value as any)[first] : '';
  }
  return value ?? '';
}

export function coerceRuleInput(value: string, mode: 'text' | 'number' | 'boolean' | 'list' = 'text') {
  if (mode === 'number') return value === '' ? '' : Number(value);
  if (mode === 'boolean') return value === 'true';
  if (mode === 'list') return value.split(',').map((part) => part.trim()).filter(Boolean);
  return value;
}

export function summarizeRule(rule: any) {
  if (!rule) return 'New rule';
  if (rule.type === 'token_budget' || rule.limit_usd !== undefined) return summarizeBudgetRule(rule);
  return rule.title
    || rule.name
    || rule.description
    || rule.reason
    || [rule.type, rule.tool, Object.keys(rule).find((key) => String(key).startsWith('classifier:'))?.replace('classifier:', '')].filter(Boolean).join(' · ')
    || 'Untitled rule';
}

export function semanticRuleFingerprint(rule: any): string {
  if (!rule || typeof rule !== 'object') return stableStringify(rule);
  const clone: any = {};
  for (const [key, value] of Object.entries(rule || {})) {
    if (['enabled', 'priority', 'description', 'reason', 'title', 'name'].includes(key)) continue;
    clone[key] = value;
  }
  return stableStringify(clone);
}

const RULE_META_KEYS = new Set(['enabled', 'priority', 'description', 'reason', 'title', 'name']);

function containsNeedle(actual: any, needle: string): boolean {
  if (needle === '' || needle === undefined || needle === null) return false;
  const n = String(needle).toLowerCase();
  if (actual === undefined || actual === null) return false;
  if (typeof actual === 'object') {
    if (Array.isArray(actual)) return actual.some((v) => containsNeedle(v, needle));
    return Object.values(actual).some((v) => containsNeedle(v, needle));
  }
  return String(actual).toLowerCase().includes(n);
}

function matchOperatorSpec(actual: any, spec: Record<string, any>): boolean {
  let matched = false;
  for (const [operator, expectedValue] of Object.entries(spec || {})) {
    matched = true;
    if (operator === 'exists') return (actual !== undefined && actual !== null) === Boolean(expectedValue);
    if (actual === undefined || actual === null) return false;
    if (operator === 'contains') return containsNeedle(actual, String(expectedValue ?? ''));
    if (operator === 'eq') return String(actual).toLowerCase() === String(expectedValue ?? '').toLowerCase();
    if (operator === 'startswith') return String(actual).toLowerCase().startsWith(String(expectedValue ?? '').toLowerCase());
    if (operator === 'endswith') return String(actual).toLowerCase().endsWith(String(expectedValue ?? '').toLowerCase());
    if (operator === 'in') {
      const values = Array.isArray(expectedValue) ? expectedValue : [expectedValue];
      const expected = new Set(values.map((v) => String(v ?? '').toLowerCase()).filter((v) => v !== ''));
      if (!expected.size) return false;
      if (Array.isArray(actual)) return actual.some((v) => expected.has(String(v).toLowerCase()));
      return expected.has(String(actual).toLowerCase());
    }
    if (operator === 'gte') {
      try {
        return Number(actual) >= Number(expectedValue);
      } catch {
        return false;
      }
    }
    if (operator === 'lte') {
      try {
        return Number(actual) <= Number(expectedValue);
      } catch {
        return false;
      }
    }
    return false;
  }
  return matched;
}

function policyFieldActual(event: any, fieldKey: string): any {
  if (fieldKey === 'tool') return event?.tool;
  if (fieldKey === 'type') return event?.action_type;
  if (fieldKey === 'url') return event?.action_url ?? null;
  if (fieldKey === 'domain') return event?.domain ?? null;
  if (fieldKey === 'risk_score') return event?.risk_score ?? 0;
  if (fieldKey === 'min_risk_score') return event?.risk_score ?? 0;
  if (fieldKey.startsWith('metadata.')) {
    let cur = event?.action_metadata;
    for (const part of fieldKey.split('.').slice(1)) {
      if (!cur || typeof cur !== 'object') return null;
      cur = cur[part];
    }
    return cur;
  }
  if (fieldKey.startsWith('args.')) {
    const args = event?.action_args;
    if (!args || typeof args !== 'object') return null;
    let cur: any = args;
    for (const part of fieldKey.split('.').slice(1)) {
      if (cur == null) return null;
      if (typeof cur === 'object' && part in cur) cur = cur[part];
      else return null;
    }
    return cur;
  }
  return null;
}

/** True when the rule has match keys beyond bare type/tool (so we can disambiguate duplicate titles). */
export function ruleHasStructuralPredicates(rule: any): boolean {
  if (!rule || typeof rule !== 'object') return false;
  for (const key of Object.keys(rule)) {
    if (RULE_META_KEYS.has(key)) continue;
    if (key === 'type' || key === 'tool') continue;
    if (key.startsWith('classifier:')) return true;
    if (key.startsWith('field:')) return true;
    if (key === 'min_risk_score') return true;
  }
  return false;
}

/**
 * Lightweight client-side rule predicate check for dashboard rollups.
 * Expects normalizeEventRow to attach action_type, action_args, action_metadata, action_url when available.
 */
export function rulePredicatesMatchEvent(event: any, rule: any): boolean {
  if (!rule || typeof rule !== 'object') return false;
  let hasPredicate = false;
  for (const [rawKey, expected] of Object.entries(rule)) {
    if (RULE_META_KEYS.has(rawKey)) continue;
    if (expected === null || expected === '') continue;
    hasPredicate = true;
    if (rawKey === 'type') {
      if (String(event?.action_type || '').toLowerCase() !== String(expected).toLowerCase()) return false;
      continue;
    }
    if (rawKey === 'tool') {
      if (String(event?.tool || '').toLowerCase() !== String(expected).toLowerCase()) return false;
      continue;
    }
    if (rawKey.startsWith('classifier:')) {
      const name = rawKey.slice('classifier:'.length);
      const actual = (event?.classifiers || {})[name];
      if (typeof expected === 'boolean') {
        if (Boolean(actual) !== expected) return false;
      } else if (String(actual || '').toLowerCase() !== String(expected).toLowerCase()) {
        return false;
      }
      continue;
    }
    if (rawKey.startsWith('field:')) {
      const path = rawKey.slice('field:'.length);
      const actual = policyFieldActual(event, path);
      if (typeof expected === 'object' && expected !== null && !Array.isArray(expected)) {
        if (!matchOperatorSpec(actual, expected as Record<string, any>)) return false;
      } else if (String(actual || '').toLowerCase() !== String(expected).toLowerCase()) {
        return false;
      }
      continue;
    }
    if (rawKey === 'min_risk_score') {
      const score = Number(event?.risk_score || 0);
      try {
        if (score < Number(expected)) return false;
      } catch {
        return false;
      }
      continue;
    }
    return false;
  }
  return hasPredicate;
}

export function summarizeRuleConditions(rule: any, max = 4) {
  const parts: string[] = [];
  if (rule?.tool) parts.push(`tool → ${rule.tool}`);
  if (rule?.type) parts.push(`type → ${String(rule.type).replace(/_/g, ' ')}`);
  for (const [key, value] of Object.entries(rule || {})) {
    if (['enabled', 'priority', 'description', 'reason', 'title', 'name', 'type', 'tool'].includes(String(key))) continue;
    if (String(key).startsWith('classifier:') && value) {
      parts.push(`classifier → ${String(key).replace('classifier:', '').replace(/_/g, ' ')}`);
      continue;
    }
    if (String(key).startsWith('field:')) {
      const operator = value && typeof value === 'object' && !Array.isArray(value) ? Object.keys(value as any)[0] : 'eq';
      const expected = value && typeof value === 'object' && !Array.isArray(value) ? (value as any)[operator] : value;
      parts.push(describeMatchedField({ field: key, operator, expected }));
    }
  }
  return parts.slice(0, max);
}

export function customRuleEntries(rule: any) {
  const dedicated = new Set([
    'enabled', 'priority', 'description', 'reason', 'title', 'name', 'type', 'tool',
    'field:url', 'field:domain', 'field:args.args', 'field:risk_score',
    'field:metadata.behavior.suspicious_sequence', 'field:metadata.behavior.previous_blocked',
  ]);
  return Object.entries(rule || {}).filter(([key]) => !dedicated.has(key) && !String(key).startsWith('classifier:'));
}
