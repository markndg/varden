/** Presentation for threat intelligence. Labels come from stored assessment fields. */

export const PAGE_SIZE = 25;

export const CONTRACT_FAMILIES = [
  { id: 'untrusted-instruction-execution', label: 'Untrusted instruction execution' },
  { id: 'credential-exfiltration', label: 'Credential exfiltration' },
  { id: 'unexpected-code-execution', label: 'Unexpected code execution' },
  { id: 'privilege-amplification', label: 'Privilege amplification' },
] as const;

const CONTRACT_LABELS: Record<string, string> = Object.fromEntries(
  CONTRACT_FAMILIES.map((row) => [row.id, row.label]),
);

export const SOURCE_LABELS: Record<string, string> = {
  atlas: 'MITRE ATLAS',
  nvd: 'NVD/CVE',
  cwe: 'CWE',
  owasp: 'OWASP Agentic',
};

export type IntelListItem = {
  id: string;
  source?: string;
  source_id?: string;
  title?: string;
  severity?: string;
  lifecycle?: string;
  applicability?: string;
  has_contract?: boolean;
  contract_id?: string | null;
  contract_version?: string | null;
  review_only?: boolean;
  review_reason?: string | null;
  mapping_ids?: string[];
  has_candidate?: boolean;
  candidate_reason_code?: string;
  rule_active?: boolean;
  surfaces?: string[];
};

export type Cell = { kind: string; text: string; detail?: string };

export function isMapped(item: Pick<IntelListItem, 'has_contract' | 'contract_id' | 'review_only'>): boolean {
  return Boolean(item.has_contract && item.contract_id && !item.review_only);
}

export function contractName(contractId?: string | null): string {
  if (!contractId) return '';
  return CONTRACT_LABELS[contractId] || contractId;
}

export function contractCell(item: IntelListItem): Cell {
  if (isMapped(item)) {
    return { kind: 'mapped', text: 'Mapped', detail: contractName(item.contract_id) };
  }
  return { kind: 'unmapped', text: 'Unmapped', detail: 'no supported Varden contract' };
}

/** One protection label. Mapped is not protected, and an installed rule is not proof. */
export function protectionCell(item: IntelListItem): Cell {
  if (item.applicability === 'PROTECTED') return { kind: 'enforced', text: 'Enforced' };
  if (item.rule_active || item.lifecycle === 'ENFORCED') return { kind: 'installed', text: 'Rule installed' };
  if (item.lifecycle === 'AWAITING_APPROVAL' && item.has_candidate) return { kind: 'awaiting', text: 'Awaiting approval' };
  if (item.has_candidate) return { kind: 'candidate', text: 'Candidate available' };
  if (item.applicability === 'NOT_APPLICABLE') return { kind: 'na', text: 'Not applicable' };
  if (item.applicability === 'EXPOSED' && isMapped(item)) {
    if (item.candidate_reason_code === 'GAP_IS_COVERAGE' || !item.has_candidate) return { kind: 'gap', text: 'Coverage gap' };
  }
  if (item.applicability === 'REVIEW' && isMapped(item)) return { kind: 'assess', text: 'Needs assessment' };
  if (!isMapped(item)) return { kind: 'unmapped', text: 'Unmapped' };
  return { kind: 'review', text: 'Review' };
}

export function applicabilityLabel(value?: string | null): string {
  switch (value) {
    case 'PROTECTED': return 'Protected';
    case 'EXPOSED': return 'Exposed';
    case 'NOT_APPLICABLE': return 'Not applicable';
    case 'REVIEW': return 'Review';
    default: return value ? value : 'Unknown';
  }
}

export function sourceLabel(source?: string): string {
  if (!source) return 'Unknown source';
  return SOURCE_LABELS[source] || source;
}

export function indexedCaption(scope?: string | null): string {
  switch (scope) {
    case 'techniques_in_upstream_document':
      return 'Techniques in the fetched document';
    case 'weaknesses_in_upstream_catalog':
      return 'Catalog index. Only bound weaknesses are stored as threats.';
    case 'records_retrieved':
      return 'Retrieved by the configured query, not the full CVE catalog';
    case 'unsupported':
      return 'Not consumed';
    default:
      return 'Not fetched yet';
  }
}

export function sourceHealthLabel(source: { health?: string; unsupported?: boolean; implementation?: string }): string {
  if (source.unsupported || source.implementation === 'scaffold' || source.health === 'unsupported') return 'Unsupported';
  switch (source.health) {
    case 'healthy': return 'Healthy';
    case 'degraded': return 'Degraded';
    case 'error': return 'Error';
    case 'unknown': return 'Not checked';
    default: return source.health || 'Not checked';
  }
}

export function actionableEmptyCopy(reason?: string | null, message?: string | null): string | null {
  if (!reason) return null;
  if (message) return message;
  return null;
}

export type ItemQuery = {
  q?: string;
  source?: string;
  mapping?: string;
  applicability?: string;
  severity?: string;
  surface?: string;
  view?: string;
  sort?: string;
  order?: string;
  page?: number;
  pageSize?: number;
};

export function buildItemQuery(filters: ItemQuery): string {
  const pageSize = filters.pageSize || PAGE_SIZE;
  const page = Math.max(filters.page || 1, 1);
  const params = new URLSearchParams();
  params.set('limit', String(pageSize));
  params.set('offset', String((page - 1) * pageSize));
  params.set('sort', filters.sort || 'priority');
  params.set('order', filters.order || 'asc');
  if (filters.q) params.set('q', filters.q);
  if (filters.source) params.set('source', filters.source);
  if (filters.mapping) params.set('mapping', filters.mapping);
  if (filters.applicability) params.set('applicability', filters.applicability);
  if (filters.severity) params.set('severity', filters.severity);
  if (filters.surface) params.set('surface', filters.surface);
  if (filters.view) params.set('view', filters.view);
  return params.toString();
}

export function pageWindow(total: number, page: number, pageSize = PAGE_SIZE) {
  const safeTotal = Math.max(0, total);
  const pages = Math.max(1, Math.ceil(safeTotal / pageSize) || 1);
  const current = Math.min(Math.max(page, 1), pages);
  const start = safeTotal === 0 ? 0 : (current - 1) * pageSize + 1;
  const end = Math.min(current * pageSize, safeTotal);
  return { pages, current, start, end, pageSize };
}
