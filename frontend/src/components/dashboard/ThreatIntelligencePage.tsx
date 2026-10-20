import { useEffect, useState, type ReactNode } from 'react';
import {
  CONTRACT_FAMILIES,
  PAGE_SIZE,
  applicabilityLabel,
  buildItemQuery,
  contractCell,
  contractName,
  indexedCaption,
  isMapped,
  pageWindow,
  protectionCell,
  sourceHealthLabel,
  sourceLabel,
  type IntelListItem,
} from '../../lib/threatIntelligence';

function watcherLabel(value?: string) {
  if (!value) return 'OFFLINE';
  if (value === 'DISABLED') return 'OFFLINE/DISABLED';
  return value;
}

function dotClass(value?: string) {
  const state = (value || 'OFFLINE').toLowerCase();
  if (state === 'disabled') return 'tiDot tiDot--disabled';
  return `tiDot tiDot--${state}`;
}

function relativeTime(epoch?: number | null) {
  if (!epoch) return 'never';
  const delta = Date.now() / 1000 - epoch;
  const abs = Math.abs(delta);
  const suffix = delta >= 0 ? 'ago' : 'from now';
  if (abs < 60) return `${Math.floor(abs)}s ${suffix}`;
  if (abs < 3600) return `${Math.floor(abs / 60)}m ${suffix}`;
  if (abs < 86400) return `${Math.floor(abs / 3600)}h ${suffix}`;
  return `${Math.floor(abs / 86400)}d ${suffix}`;
}

export function ThreatIntelIndicator({ status }: { status: any }) {
  const watcher = watcherLabel(status?.watcher);
  const fresh = Number(status?.new_items || 0);
  const actionable = status?.counts?.actionable;
  return (
    <div className="tiIndicator" aria-label="Threat intelligence watcher">
      <div className="tiIndicator__row">
        <span>Threat Intelligence</span>
        <span className="tiIndicator__state"><span className={dotClass(status?.watcher)} aria-hidden /> {watcher}</span>
      </div>
      <div className="muted tiIndicator__meta">Last successful check: {relativeTime(status?.last_success)}</div>
      <div className="muted tiIndicator__meta">{fresh} new intelligence items</div>
      <div className="muted tiIndicator__meta">
        {actionable == null ? 'Actionable count unavailable' : `${actionable} actionable`}
      </div>
      <p className="muted tiIndicator__note">Watcher status. A healthy watcher is not protection.</p>
    </div>
  );
}

async function callApi(path: string, token: string, opts: RequestInit = {}) {
  const headers = new Headers(opts.headers || {});
  if (token) {
    if (token.includes('.')) headers.set('Authorization', `Bearer ${token}`);
    else headers.set('x-api-key', token);
  }
  if (opts.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const res = await fetch(path, { ...opts, headers });
  const text = await res.text();
  let data: any = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { detail: text }; }
  if (!res.ok) throw new Error((data && (data.detail?.detail || data.detail || data.message)) || res.statusText);
  return data;
}

type Filters = {
  q: string;
  source: string;
  mapping: string;
  applicability: string;
  severity: string;
  surface: string;
  view: string;
  sort: string;
  order: string;
};

const EMPTY_FILTERS: Filters = {
  q: '',
  source: '',
  mapping: '',
  applicability: '',
  severity: '',
  surface: '',
  view: '',
  sort: 'priority',
  order: 'asc',
};

export function ThreatIntelligencePage({
  token,
  itemId,
  onOpenItem,
  onOpenList,
  onStatus,
}: {
  token: string;
  itemId: string | null;
  onOpenItem: (id: string) => void;
  onOpenList: () => void;
  onStatus: (status: any) => void;
}) {
  const [status, setStatus] = useState<any>(null);
  const [sources, setSources] = useState<any[]>([]);
  const [items, setItems] = useState<IntelListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [detail, setDetail] = useState<any>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [loading, setLoading] = useState(false);
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
  const [search, setSearch] = useState('');

  useEffect(() => {
    const handle = window.setTimeout(() => {
      setFilters((current) => (current.q === search ? current : { ...current, q: search }));
      setPage(1);
    }, 250);
    return () => window.clearTimeout(handle);
  }, [search]);

  useEffect(() => {
    if (!token) return;
    let stop = false;
    callApi('/threat-intelligence/status', token).then((payload) => {
      if (stop) return;
      setStatus(payload);
      onStatus(payload);
    }).catch((err) => { if (!stop) setError(err.message || 'status failed'); });
    callApi('/threat-intelligence/sources', token).then((payload) => {
      if (!stop) setSources(payload.sources || []);
    }).catch(() => {});
    callApi('/threat-intelligence/seen', token, { method: 'POST', body: '{}' }).catch(() => {});
    return () => { stop = true; };
  }, [token]);

  useEffect(() => {
    if (!token || itemId) return;
    let stop = false;
    setLoading(true);
    const query = buildItemQuery({ ...filters, page });
    callApi(`/threat-intelligence/items?${query}`, token).then((payload) => {
      if (stop) return;
      setItems(payload.items || []);
      setTotal(Number(payload.total || 0));
      setLoading(false);
    }).catch((err) => {
      if (!stop) {
        setError(err.message || 'list failed');
        setLoading(false);
      }
    });
    return () => { stop = true; };
  }, [token, filters, page, itemId]);

  useEffect(() => {
    if (!token || !itemId) {
      setDetail(null);
      return;
    }
    let stop = false;
    setDetail(null);
    callApi(`/threat-intelligence/items/${encodeURIComponent(itemId)}`, token).then((payload) => {
      if (!stop) setDetail(payload);
    }).catch((err) => { if (!stop) setError(err.message || 'item failed'); });
    return () => { stop = true; };
  }, [token, itemId]);

  async function refreshStatus() {
    const refreshed = await callApi('/threat-intelligence/status', token);
    setStatus(refreshed);
    onStatus(refreshed);
  }

  async function act(path: string, success: string, proof?: { expected_content_hash?: string; expected_candidate_id?: string }) {
    setError('');
    setNotice('');
    try {
      const payload = await callApi(path, token, { method: 'POST', body: JSON.stringify(proof || {}) });
      setNotice(success);
      if (itemId) {
        const next = await callApi(`/threat-intelligence/items/${encodeURIComponent(itemId)}`, token);
        setDetail(next);
      }
      await refreshStatus();
      return payload;
    } catch (err: any) {
      setError(err.message || 'request failed');
    }
  }

  function patchFilters(patch: Partial<Filters>) {
    setFilters((current) => ({ ...current, ...patch }));
    setPage(1);
  }

  if (!token) {
    return <section className="card"><p>Sign in with a control-plane credential to read threat intelligence.</p></section>;
  }

  if (itemId) {
    return (
      <ThreatDetail
        detail={detail}
        error={error}
        notice={notice}
        onBack={onOpenList}
        onReplay={() => act(`/threat-intelligence/items/${encodeURIComponent(itemId)}/replay`, 'Replay finished. Stored events were evaluated. Nothing was executed.')}
        onCreate={(proof) => act(`/threat-intelligence/items/${encodeURIComponent(itemId)}/approve`, 'Rule created through Varden policy. It is active only if the lifecycle is ENFORCED.', proof)}
        onDismiss={() => act(`/threat-intelligence/items/${encodeURIComponent(itemId)}/dismiss`, 'Dismissed. No rule was created.')}
        onReview={() => act(`/threat-intelligence/items/${encodeURIComponent(itemId)}/review`, 'Kept in review. No rule was created.')}
        onNotApplicable={() => act(`/threat-intelligence/items/${encodeURIComponent(itemId)}/not-applicable`, 'Marked not applicable. No rule was created.')}
      />
    );
  }

  const counts = status?.counts || {};
  const emptyMessage = filters.view === 'actionable' && total === 0 && !loading
    ? (status?.actionable_empty_message || null)
    : null;

  return (
    <section className="stack tiWorkspace">
      {error ? <div className="banner banner--error" role="alert">{error}</div> : null}
      {notice ? <div className="banner banner--ok">{notice}</div> : null}
      <SummaryMetrics
        counts={counts}
        meanings={status?.count_meanings || {}}
        active={filters}
        onSelect={(patch) => {
          if (patch.view === 'actionable') setSearch('');
          patchFilters({ ...EMPTY_FILTERS, sort: filters.sort, order: filters.order, ...patch });
          if (!patch.q) setSearch('');
        }}
      />
      <SourceHealthPanel sources={sources} />
      <section className="card">
        <div className="sectionHeader">
          <div>
            <div className="eyebrow">Intelligence</div>
            <h3>Results</h3>
          </div>
          <p className="muted">Mapping coverage and runtime protection are separate. A mapped contract is not an active rule.</p>
        </div>
        <FilterBar
          filters={filters}
          search={search}
          onSearch={setSearch}
          onChange={patchFilters}
        />
        <IntelligenceTable
          items={items}
          total={total}
          page={page}
          sort={filters.sort}
          order={filters.order}
          loading={loading}
          emptyMessage={emptyMessage}
          onOpen={onOpenItem}
          onSort={(sort) => {
            const order = filters.sort === sort && filters.order === 'asc' ? 'desc' : 'asc';
            patchFilters({ sort, order });
          }}
          onPage={setPage}
        />
      </section>
    </section>
  );
}

export function SummaryMetrics({
  counts,
  meanings,
  active,
  onSelect,
}: {
  counts: Record<string, number>;
  meanings: Record<string, string>;
  active?: Partial<Filters>;
  onSelect?: (patch: Partial<Filters>) => void;
}) {
  const cards = [
    { key: 'total', label: 'Total intelligence', patch: { ...EMPTY_FILTERS } },
    { key: 'mapped', label: 'Contracts mapped', patch: { mapping: 'mapped', view: '' } },
    { key: 'unmapped', label: 'Unmapped', patch: { mapping: 'unmapped', view: '' } },
    { key: 'exposed', label: 'Exposed', patch: { applicability: 'EXPOSED', view: '' } },
    { key: 'protected', label: 'Protected', patch: { applicability: 'PROTECTED', view: '' } },
    { key: 'candidates_awaiting', label: 'Awaiting approval', patch: { view: 'actionable' } },
  ];
  return (
    <section className="card" aria-label="Installation summary">
      <div className="sectionHeader">
        <div>
          <div className="eyebrow">Advisory</div>
          <h3>Installation summary</h3>
        </div>
        <p className="muted">These counts describe stored assessments. They do not mean the firewall is enforcing them.</p>
      </div>
      <div className="tiMetrics">
        {cards.map((card) => (
          <button
            key={card.key}
            type="button"
            className={`tiMetric${active && metricActive(active, card.key) ? ' is-active' : ''}`}
            title={meanings[card.key] || ''}
            onClick={() => onSelect?.(card.patch)}
          >
            <span>{card.label}</span>
            <strong>{counts[card.key] || 0}</strong>
            <small>{meanings[card.key] || ''}</small>
          </button>
        ))}
      </div>
      <div className="tiSecondary" aria-label="Other assessment counts">
        <button type="button" className="button button--ghost" onClick={() => onSelect?.({ applicability: 'REVIEW', mapping: '', view: '' })}>
          Review {counts.review || 0}
        </button>
        <button type="button" className="button button--ghost" onClick={() => onSelect?.({ applicability: 'NOT_APPLICABLE', mapping: '', view: '' })}>
          Not applicable {counts.not_applicable || 0}
        </button>
        <button type="button" className="button button--ghost" onClick={() => onSelect?.({ view: 'actionable', mapping: '', applicability: '' })}>
          Actionable {counts.actionable || 0}
        </button>
      </div>
    </section>
  );
}

function metricActive(filters: Partial<Filters>, key: string) {
  if (key === 'mapped') return filters.mapping === 'mapped';
  if (key === 'unmapped') return filters.mapping === 'unmapped';
  if (key === 'exposed') return filters.applicability === 'EXPOSED';
  if (key === 'protected') return filters.applicability === 'PROTECTED';
  if (key === 'candidates_awaiting') return filters.view === 'actionable';
  return !filters.mapping && !filters.applicability && !filters.view && !filters.source && !filters.severity && !filters.surface && !filters.q;
}

export function SourceHealthPanel({ sources }: { sources: any[] }) {
  return (
    <section className="card">
      <div className="sectionHeader">
        <div>
          <div className="eyebrow">Sources</div>
          <h3>Feed health</h3>
        </div>
        <p className="muted">A healthy feed means the last fetch succeeded. It is not proof of protection.</p>
      </div>
      <div className="tiTableWrap">
        <table className="tiTable">
          <thead>
            <tr>
              <th>Source</th>
              <th>Health</th>
              <th>Last success</th>
              <th>Indexed</th>
              <th>Mapped</th>
              <th>Next check</th>
            </tr>
          </thead>
          <tbody>
            {sources.length ? sources.map((source) => {
              const health = sourceHealthLabel(source);
              return (
                <tr key={source.source_id}>
                  <td data-label="Source">
                    <div className="tiThreat__title">{source.title}</div>
                    {source.source_version ? <div className="tiThreat__id">Version {source.source_version}</div> : null}
                  </td>
                  <td data-label="Health"><span className={`tiPill tiPill--${health.toLowerCase().replace(/\s+/g, '-')}`}>{health}</span></td>
                  <td data-label="Last success">{relativeTime(source.last_success)}</td>
                  <td data-label="Indexed">
                    <div>{source.records_indexed ?? 0}</div>
                    <div className="tiThreat__id">{indexedCaption(source.records_indexed_scope)}</div>
                  </td>
                  <td data-label="Mapped">{source.records_mapped ?? 0}</td>
                  <td data-label="Next check">{source.unsupported ? 'Not scheduled' : relativeTime(source.next_due)}</td>
                </tr>
              );
            }) : (
              <tr><td colSpan={6} className="muted">Source status has not loaded.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function FilterBar({
  filters,
  search,
  onSearch,
  onChange,
}: {
  filters: Filters;
  search: string;
  onSearch: (value: string) => void;
  onChange: (patch: Partial<Filters>) => void;
}) {
  return (
    <div className="tiToolbar" role="search">
      <label className="tiField tiField--search">
        <span>Search</span>
        <input className="input" value={search} placeholder="Identifier or title" aria-label="Search by identifier or title" onChange={(event) => onSearch(event.target.value)} />
      </label>
      <Field label="Source" value={filters.source} onChange={(source) => onChange({ source })}>
        <option value="">All</option>
        <option value="atlas">MITRE ATLAS</option>
        <option value="nvd">NVD/CVE</option>
        <option value="cwe">CWE</option>
        <option value="owasp">OWASP</option>
      </Field>
      <Field label="Mapping" value={filters.mapping} onChange={(mapping) => onChange({ mapping, view: '' })}>
        <option value="">All</option>
        <option value="mapped">Mapped</option>
        <option value="unmapped">Unmapped</option>
      </Field>
      <Field label="Applicability" value={filters.applicability} onChange={(applicability) => onChange({ applicability })}>
        <option value="">All</option>
        <option value="PROTECTED">Protected</option>
        <option value="EXPOSED">Exposed</option>
        <option value="REVIEW">Review</option>
        <option value="NOT_APPLICABLE">Not applicable</option>
      </Field>
      <Field label="Severity" value={filters.severity} onChange={(severity) => onChange({ severity })}>
        <option value="">All</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="unknown">Unknown</option>
      </Field>
      <Field label="Surface" value={filters.surface} onChange={(surface) => onChange({ surface })}>
        <option value="">All</option>
        <option value="http">HTTP</option>
        <option value="mcp">MCP</option>
        <option value="filesystem">Filesystem</option>
        <option value="subprocess">Subprocess</option>
        <option value="tools">Tools</option>
      </Field>
      <div className="tiField tiField--view">
        <span>View</span>
        <button
          type="button"
          className={`button button--ghost${filters.view === 'actionable' ? ' is-active' : ''}`}
          aria-pressed={filters.view === 'actionable'}
          onClick={() => onChange({ view: filters.view === 'actionable' ? '' : 'actionable' })}
        >
          Actionable
        </button>
      </div>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  children,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  children: ReactNode;
}) {
  return (
    <label className="tiField">
      <span>{label}</span>
      <select className="input" aria-label={`Filter by ${label.toLowerCase()}`} value={value} onChange={(event) => onChange(event.target.value)}>
        {children}
      </select>
    </label>
  );
}

const COLUMNS: { key: string; label: string; sortable?: boolean }[] = [
  { key: 'title', label: 'Threat' },
  { key: 'source_id', label: 'Source' },
  { key: 'contract', label: 'Contract', sortable: false },
  { key: 'applicability', label: 'Applicability' },
  { key: 'protection', label: 'Protection', sortable: false },
  { key: 'action', label: 'Action', sortable: false },
];

export function IntelligenceTable({
  items,
  total,
  page,
  sort,
  order,
  loading,
  emptyMessage,
  onOpen,
  onSort,
  onPage,
}: {
  items: IntelListItem[];
  total: number;
  page: number;
  sort: string;
  order: string;
  loading?: boolean;
  emptyMessage?: string | null;
  onOpen: (id: string) => void;
  onSort: (sort: string) => void;
  onPage: (page: number) => void;
}) {
  const window = pageWindow(total, page, PAGE_SIZE);
  return (
    <div>
      <div className="tiTableWrap">
        <table className="tiTable">
          <caption className="srOnly">Threat intelligence records</caption>
          <thead>
            <tr>
              {COLUMNS.map((column) => (
                <th key={column.label} aria-sort={column.sortable === false ? undefined : sort === column.key ? (order === 'asc' ? 'ascending' : 'descending') : 'none'}>
                  {column.sortable === false ? column.label : (
                    <button type="button" className="tiSort" onClick={() => onSort(column.key)}>{column.label}</button>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading && !items.length ? (
              <tr><td colSpan={6} className="muted">Loading intelligence…</td></tr>
            ) : null}
            {!loading && !items.length ? (
              <tr><td colSpan={6}>{emptyMessage || 'No stored intelligence matches this filter.'}</td></tr>
            ) : null}
            {items.map((item) => {
              const contract = contractCell(item);
              const protection = protectionCell(item);
              return (
                <tr key={item.id}>
                  <td data-label="Threat">
                    <button type="button" className="tiLink" onClick={() => onOpen(item.id)}>{item.title || item.source_id}</button>
                    <div className="tiThreat__id">{item.source_id}</div>
                  </td>
                  <td data-label="Source">{sourceLabel(item.source)}</td>
                  <td data-label="Contract">
                    <span className={`tiPill tiPill--${contract.kind}`}>{contract.text}</span>
                    <div className="tiThreat__id">{contract.detail}</div>
                  </td>
                  <td data-label="Applicability"><span className={`tiPill tiPill--${(item.applicability || 'review').toLowerCase()}`}>{applicabilityLabel(item.applicability)}</span></td>
                  <td data-label="Protection"><span className={`tiPill tiPill--${protection.kind}`}>{protection.text}</span></td>
                  <td data-label="Action">
                    <button type="button" className="button button--ghost" onClick={() => onOpen(item.id)}>Investigate</button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <div className="tiPager">
        <span className="muted">{total ? `${window.start}–${window.end} of ${total}` : '0 records'}</span>
        <div className="tiPager__controls">
          <button type="button" className="button button--ghost" disabled={window.current <= 1} onClick={() => onPage(window.current - 1)}>Previous</button>
          <span>Page {window.current} of {window.pages}</span>
          <button type="button" className="button button--ghost" disabled={window.current >= window.pages} onClick={() => onPage(window.current + 1)}>Next</button>
        </div>
      </div>
    </div>
  );
}

export function ThreatDetail({
  detail,
  error,
  notice,
  onBack,
  onCreate,
  onDismiss,
  onReview,
  onNotApplicable,
  onReplay,
}: {
  detail: any;
  error: string;
  notice: string;
  onBack: () => void;
  onCreate: (proof: { expected_content_hash?: string; expected_candidate_id?: string }) => void;
  onDismiss: () => void;
  onReview: () => void;
  onNotApplicable: () => void;
  onReplay?: () => void;
}) {
  if (!detail) return <section className="card"><p className="muted">Loading threat…</p></section>;
  const contract = detail.contract || {};
  const assessment = detail.assessment || {};
  const candidate = detail.candidate || {};
  const replay = detail.replay || {};
  const mapped = isMapped({
    has_contract: Boolean(contract.id),
    contract_id: contract.id,
    review_only: Boolean(contract.review_only),
  });
  const listShape: IntelListItem = {
    id: detail.id,
    applicability: assessment.result || detail.applicability,
    has_contract: mapped,
    contract_id: contract.id,
    review_only: Boolean(contract.review_only),
    has_candidate: Boolean(candidate.possible),
    candidate_reason_code: candidate.reason_code,
    lifecycle: detail.lifecycle,
    rule_active: Boolean(detail.rule_active),
  };
  const protection = protectionCell(listShape);
  const canApprove = detail.lifecycle === 'AWAITING_APPROVAL' && candidate.possible;
  return (
    <section className="stack">
      {error ? <div className="banner banner--error" role="alert">{error}</div> : null}
      {notice ? <div className="banner banner--ok">{notice}</div> : null}
      <div className="tiDetail__bar">
        <button type="button" className="button button--ghost" onClick={onBack}>Back to intelligence</button>
        <span className={`tiPill tiPill--${protection.kind}`}>{protection.text}</span>
      </div>
      <section className="card">
        <div className="eyebrow">External intelligence</div>
        <h3>{detail.title}</h3>
        <p className="tiProse">{detail.description}</p>
        <p className="muted">{sourceLabel(detail.source)} · {detail.source_id} · {detail.severity || 'unknown severity'}</p>
      </section>
      <section className="card">
        <div className="eyebrow">Source provenance</div>
        <dl className="tiDefs">
          <div><dt>Source</dt><dd>{sourceLabel(detail.source)}</dd></div>
          <div><dt>Identifier</dt><dd>{detail.source_id}</dd></div>
          <div><dt>Source version</dt><dd>{detail.source_version || 'Not recorded'}</dd></div>
          <div><dt>Content hash</dt><dd className="tiMono">{detail.raw_content_hash}</dd></div>
          <div><dt>Upstream</dt><dd className="tiMono">{detail.upstream_url || 'Not recorded'}</dd></div>
        </dl>
        <ul className="tiRefs">
          {(detail.references || []).map((ref: any, index: number) => (
            <li key={index}>{ref.accepted ? ref.url : `Rejected reference (${ref.reason})`}</li>
          ))}
        </ul>
      </section>
      <section className="card">
        <div className="eyebrow">Varden interpretation</div>
        {mapped ? <p>{contract.explanation}</p> : <UnmappedExplanation contract={contract} />}
      </section>
      <section className="card">
        <div className="eyebrow">Security contract</div>
        {mapped ? <ContractBody contract={contract} /> : (
          <p>No security contract was generated. Varden does not invent an invariant for an identifier outside the binding table.</p>
        )}
      </section>
      <section className="card">
        <div className="eyebrow">Runtime applicability</div>
        <h3>{applicabilityLabel(assessment.result || detail.applicability)}</h3>
        <ul>{(assessment.reasons || []).map((reason: string) => <li key={reason}>{reason}</li>)}</ul>
        {(assessment.surfaces || []).length ? (
          <table className="tiTable">
            <thead><tr><th>Surface</th><th>Applicable</th><th>Coverage</th></tr></thead>
            <tbody>
              {(assessment.surfaces || []).map((row: any) => (
                <tr key={row.name}>
                  <td>{row.name}</td>
                  <td>{row.applicable ? 'Applicable' : 'Not applicable'}</td>
                  <td>{row.coverage}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <p className="muted">No surface assessment, because this record has no contract to evaluate.</p>}
      </section>
      <section className="card">
        <div className="eyebrow">Candidate protection</div>
        {candidate.possible ? (
          <>
            <p>{candidate.explanation}</p>
            <p className="muted">Expected action: {candidate.expected_action}. Confidence: {candidate.confidence}. {detail.rule_active ? 'This rule is in Varden policy.' : 'This rule is not active.'}</p>
            <ul>{(candidate.assumptions || []).map((row: string) => <li key={row}>{row}</li>)}</ul>
            {(candidate.conflicts || []).length ? <ul>{candidate.conflicts.map((row: any, index: number) => <li key={index}>Conflict in {row.bucket}: {row.note}</li>)}</ul> : null}
            <pre className="paPre">{JSON.stringify(candidate.rule, null, 2)}</pre>
          </>
        ) : (
          <p>{candidate.explanation || contract.review_reason || 'No candidate rule. A candidate is offered only when a mapped contract has an applicable gap that a Varden predicate can close.'}</p>
        )}
      </section>
      <section className="card">
        <div className="eyebrow">Historical replay</div>
        <p className="muted">Status: {replay.status || 'not run'}. Replay reads stored events. It does not call tools, contact the network, or write policy.</p>
        <div className="tiCounts">
          <Count label="Analysed" value={replay.operations_analysed || 0} />
          <Count label="Unaffected" value={replay.unaffected || 0} />
          <Count label="Allow" value={replay.would_allow || 0} />
          <Count label="Challenged" value={replay.would_challenge || 0} />
          <Count label="Approval" value={replay.would_require_approval || 0} />
          <Count label="Deny" value={replay.would_deny || 0} />
          <Count label="Unknown" value={replay.unknown || 0} />
        </div>
        {replay.reason ? <p>{replay.reason}</p> : null}
        <ul>
          {(replay.affected || []).slice(0, 20).map((row: any, index: number) => (
            <li key={index}>Event {row.event_id}: {row.before} → {row.after}</li>
          ))}
        </ul>
        {onReplay ? <button type="button" className="button button--ghost" onClick={onReplay}>Run replay</button> : null}
      </section>
      <section className="card">
        <div className="eyebrow">Decision</div>
        <p className="muted">{detail.rule_active ? 'This candidate has been written into Varden policy. Protection still depends on coverage proof.' : 'Nothing here is enforcing until Create Rule succeeds and applicability is proven.'}</p>
        <div className="tiActions">
          <button type="button" className="button" disabled={!canApprove} onClick={() => onCreate({ expected_content_hash: detail.raw_content_hash, expected_candidate_id: candidate.id })}>Create Rule</button>
          <button type="button" className="button button--ghost" onClick={onDismiss}>Dismiss</button>
          <button type="button" className="button button--ghost" onClick={onReview}>Keep in Review</button>
          <button type="button" className="button button--ghost" onClick={onNotApplicable}>Mark Not Applicable</button>
        </div>
      </section>
    </section>
  );
}

function UnmappedExplanation({ contract }: { contract: any }) {
  const reason = contract.review_reason || contract.explanation || 'No deterministic Varden contract is bound to the structured identifiers in this record.';
  return (
    <div className="tiExplain">
      <p><strong>Unmapped — no supported Varden contract.</strong></p>
      <p>{reason}</p>
      <p>Varden selects a contract only from an explicit identifier binding. The title and description of this record are not used.</p>
      <p>Current contract families: {CONTRACT_FAMILIES.map((row) => row.label).join(', ')}. This record is not in that table.</p>
      {(contract.mapping_ids || []).length ? <p>Identifiers considered: {Array.from(new Set(contract.mapping_ids || [])).join(', ')}.</p> : null}
      <p>No enforcement surface is claimed, because there is no invariant to prove. A future binding would have to name both the invariant and a Varden control that can prove it.</p>
    </div>
  );
}

function ContractBody({ contract }: { contract: any }) {
  return (
    <div>
      <h3>{contractName(contract.id)}</h3>
      <dl className="tiDefs">
        <div><dt>Contract</dt><dd>{contract.id}</dd></div>
        <div><dt>Version</dt><dd>{contract.version || 'unknown'}</dd></div>
        <div><dt>Mapping version</dt><dd>{contract.mapping_version || 'unknown'}</dd></div>
        <div><dt>Invariant</dt><dd>{contract.invariant}</dd></div>
        <div><dt>Identifiers</dt><dd>{Array.from(new Set(contract.mapping_ids || [])).join(', ') || 'None recorded'}</dd></div>
        <div><dt>Required surfaces</dt><dd>{(contract.required_surfaces || []).join(', ') || 'None'}</dd></div>
        <div><dt>Required observability</dt><dd>{(contract.required_observability || []).join(', ') || 'None'}</dd></div>
      </dl>
      <p>{contract.explanation}</p>
      <pre className="paPre">{JSON.stringify(contract.proof, null, 2)}</pre>
    </div>
  );
}

function Count({ label, value }: { label: string; value: number }) {
  return <div className="tiCount"><span className="muted">{label}</span><strong>{value}</strong></div>;
}
