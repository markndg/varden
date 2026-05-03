import { PolicyDoc, RULE_BUCKETS } from './types';

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
  };
}

export function mergePolicyWithoutDuplicates(baseDoc: PolicyDoc, templateDoc: PolicyDoc): PolicyDoc {
  return dedupePolicyDoc({
    block: [...baseDoc.block, ...templateDoc.block],
    warn: [...baseDoc.warn, ...templateDoc.warn],
    monitor: [...baseDoc.monitor, ...templateDoc.monitor],
    allow: [...baseDoc.allow, ...templateDoc.allow],
  });
}

export function pickFirstNonEmptyBucket(doc: PolicyDoc): typeof RULE_BUCKETS[number] {
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
