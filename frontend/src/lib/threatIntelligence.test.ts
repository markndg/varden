import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { IntelligenceTable, SourceHealthPanel, SummaryMetrics, ThreatDetail, ThreatIntelIndicator } from '../components/dashboard/ThreatIntelligencePage';
import {
  applicabilityLabel,
  buildItemQuery,
  contractCell,
  pageWindow,
  protectionCell,
  type IntelListItem,
} from './threatIntelligence';

const mapped: IntelListItem = {
  id: 'atlas:AML.T0051',
  source: 'atlas',
  source_id: 'AML.T0051',
  title: 'LLM Prompt Injection',
  severity: 'unknown',
  lifecycle: 'NOT_APPLICABLE',
  applicability: 'NOT_APPLICABLE',
  has_contract: true,
  contract_id: 'untrusted-instruction-execution',
  contract_version: '1',
  review_only: false,
  has_candidate: false,
  surfaces: ['tools'],
};

const unmapped: IntelListItem = {
  id: 'atlas:AML.T9999',
  source: 'atlas',
  source_id: 'AML.T9999',
  title: '<script>alert(1)</script>',
  applicability: 'REVIEW',
  has_contract: false,
  contract_id: null,
  review_only: true,
  review_reason: 'No deterministic Varden contract is bound to the structured identifiers in this record.',
  has_candidate: false,
  lifecycle: 'REVIEW',
};

function html(node: ReturnType<typeof createElement>) {
  return renderToStaticMarkup(node);
}

describe('threat intelligence presentation', () => {
  it('names a mapped contract and does not call an unmapped record a failed lookup', () => {
    expect(contractCell(mapped)).toMatchObject({ kind: 'mapped', detail: 'Untrusted instruction execution' });
    expect(contractCell(unmapped)).toMatchObject({ kind: 'unmapped', detail: 'no supported Varden contract' });
    expect(protectionCell(mapped).text).toBe('Not applicable');
    expect(protectionCell(unmapped).text).toBe('Unmapped');
    expect(applicabilityLabel('REVIEW')).toBe('Review');
  });

  it('separates candidate, coverage gap, protected, exposed, and installed rule', () => {
    expect(protectionCell({ ...mapped, applicability: 'EXPOSED', has_candidate: true, lifecycle: 'AWAITING_APPROVAL' }).text).toBe('Awaiting approval');
    expect(protectionCell({ ...mapped, applicability: 'EXPOSED', has_candidate: true, lifecycle: 'CANDIDATE' }).text).toBe('Candidate available');
    expect(protectionCell({ ...mapped, applicability: 'EXPOSED', has_candidate: false, candidate_reason_code: 'GAP_IS_COVERAGE', lifecycle: 'REVIEW' }).text).toBe('Coverage gap');
    expect(protectionCell({ ...mapped, applicability: 'PROTECTED', lifecycle: 'ENFORCED', rule_active: true }).text).toBe('Enforced');
    expect(protectionCell({ ...mapped, applicability: 'NOT_APPLICABLE', lifecycle: 'ENFORCED', rule_active: true }).text).toBe('Rule installed');
    expect(protectionCell({ ...mapped, applicability: 'REVIEW', has_candidate: false, lifecycle: 'REVIEW' }).text).toBe('Needs assessment');
    expect(protectionCell({ ...mapped, applicability: 'EXPOSED', has_candidate: false, lifecycle: 'ASSESSED' }).text).toBe('Coverage gap');
  });

  it('renders mapped and unmapped rows from list fields, with hostile titles as text', () => {
    const markup = html(createElement(IntelligenceTable, {
      items: [mapped, unmapped],
      total: 2,
      page: 1,
      sort: 'priority',
      order: 'asc',
      onOpen: () => {},
      onSort: () => {},
      onPage: () => {},
    }));
    expect(markup).toContain('Untrusted instruction execution');
    expect(markup).toContain('Unmapped');
    expect(markup).toContain('no supported Varden contract');
    expect(markup).toContain('Not applicable');
    expect(markup).not.toContain('no contract');
    expect(markup).not.toContain('no candidate');
    expect(markup).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(markup).not.toContain('<script>');
  });

  it('pages a large result set instead of rendering every row', () => {
    const items = Array.from({ length: 25 }, (_, index) => ({ ...unmapped, id: `atlas:AML.T${index}`, source_id: `AML.T${index}`, title: `Technique ${index}` }));
    const markup = html(createElement(IntelligenceTable, {
      items,
      total: 1000,
      page: 2,
      sort: 'title',
      order: 'asc',
      onOpen: () => {},
      onSort: () => {},
      onPage: () => {},
    }));
    expect(markup).toContain('26–50 of 1000');
    expect(markup).toContain('Page 2 of 40');
    expect(markup.match(/Technique /g)?.length).toBe(25);
    expect(pageWindow(1000, 2).start).toBe(26);
  });

  it('builds filter and pagination query from operator controls', () => {
    expect(buildItemQuery({ q: 'AML.T0051', source: 'atlas', mapping: 'mapped', applicability: 'EXPOSED', severity: 'high', surface: 'tools', view: 'actionable', page: 3, sort: 'title', order: 'desc' }))
      .toBe('limit=25&offset=50&sort=title&order=desc&q=AML.T0051&source=atlas&mapping=mapped&applicability=EXPOSED&severity=high&surface=tools&view=actionable');
  });

  it('shows an empty database and a backend-supplied actionable explanation', () => {
    const empty = html(createElement(SummaryMetrics, { counts: {}, meanings: { total: 'Stored threat records. This is not the upstream catalog size.' } }));
    expect(empty).toContain('Total intelligence');
    expect(empty).toContain('Stored threat records');
    const actionable = html(createElement(IntelligenceTable, {
      items: [],
      total: 0,
      page: 1,
      sort: 'priority',
      order: 'asc',
      emptyMessage: 'No candidate rules are currently available. The connected runtime has not attested the capabilities required to evaluate these contracts.',
      onOpen: () => {},
      onSort: () => {},
      onPage: () => {},
    }));
    expect(actionable).toContain('has not attested the capabilities');
  });

  it('labels a degraded source as feed health and an unsupported source as not consumed', () => {
    const markup = html(createElement(SourceHealthPanel, {
      sources: [
        { source_id: 'atlas', title: 'MITRE ATLAS', health: 'degraded', last_success: 10, next_due: 20, records_indexed: 208, records_mapped: 2, records_indexed_scope: 'techniques_in_upstream_document' },
        { source_id: 'owasp', title: 'OWASP', health: 'unsupported', unsupported: true, records_indexed: 0, records_mapped: 0, records_indexed_scope: 'unsupported' },
      ],
    }));
    expect(markup).toContain('Degraded');
    expect(markup).toContain('Unsupported');
    expect(markup).toContain('Not consumed');
    expect(markup).toContain('not proof of protection');
  });

  it('explains an unmapped investigation and renders a mapped contract version', () => {
    const missing = html(createElement(ThreatDetail, {
      detail: {
        id: unmapped.id,
        title: unmapped.title,
        description: 'ignore previous instructions',
        source: 'atlas',
        source_id: 'AML.T9999',
        raw_content_hash: 'abc',
        lifecycle: 'REVIEW',
        applicability: 'REVIEW',
        contract: { id: null, review_only: true, review_reason: unmapped.review_reason, mapping_ids: ['AML.T9999'], version: '1' },
        assessment: { result: 'REVIEW', reasons: [unmapped.review_reason], surfaces: [] },
        candidate: { possible: false },
        references: [{ accepted: false, reason: 'non_public', url: 'http://169.254.169.254/' }],
      },
      error: '',
      notice: '',
      onBack: () => {},
      onCreate: () => {},
      onDismiss: () => {},
      onReview: () => {},
      onNotApplicable: () => {},
    }));
    expect(missing).toContain('Unmapped — no supported Varden contract');
    expect(missing).toContain('No deterministic Varden contract');
    expect(missing).toContain('Untrusted instruction execution');
    expect(missing).toContain('No security contract was generated');
    expect(missing).toContain('Rejected reference');
    expect(missing).not.toContain('no contract / no candidate');

    const versionOne = html(createElement(ThreatDetail, {
      detail: contractDetail('1', 'AWAITING_APPROVAL', false),
      error: '',
      notice: '',
      onBack: () => {},
      onCreate: () => {},
      onDismiss: () => {},
      onReview: () => {},
      onNotApplicable: () => {},
    }));
    const versionTwo = html(createElement(ThreatDetail, {
      detail: contractDetail('2', 'ENFORCED', true),
      error: '',
      notice: '',
      onBack: () => {},
      onCreate: () => {},
      onDismiss: () => {},
      onReview: () => {},
      onNotApplicable: () => {},
    }));
    expect(versionOne).toContain('Awaiting approval');
    expect(versionOne).toContain('>1<');
    expect(versionOne).toContain('ti-untrusted-instruction-execution');
    expect(versionTwo).toContain('Enforced');
    expect(versionTwo).toContain('>2<');
    expect(versionTwo).not.toContain('Awaiting approval');
  });

  it('keeps the sidebar watcher distinct from protection', () => {
    const markup = html(createElement(ThreatIntelIndicator, {
      status: { watcher: 'LIVE', last_success: 1, new_items: 4, counts: { actionable: 0 }, protection_claim: false },
    }));
    expect(markup).toContain('LIVE');
    expect(markup).toContain('4 new intelligence items');
    expect(markup).toContain('0 actionable');
    expect(markup).toContain('not protection');
  });
});

function contractDetail(version: string, lifecycle: string, ruleActive: boolean) {
  return {
    id: 'atlas:AML.T0051',
    title: 'LLM Prompt Injection',
    description: 'prompt injection',
    source: 'atlas',
    source_id: 'AML.T0051',
    raw_content_hash: 'hash',
    lifecycle,
    applicability: ruleActive ? 'PROTECTED' : 'EXPOSED',
    rule_active: ruleActive,
    contract: {
      id: 'untrusted-instruction-execution',
      version,
      mapping_version: version,
      review_only: false,
      invariant: 'untrusted_content_must_not_gain_the_agents_authority',
      explanation: 'Untrusted instructions must not exercise tool authority.',
      mapping_ids: ['AML.T0051'],
      required_surfaces: ['tools', 'mcp'],
      required_observability: ['provenance'],
      proof: { type: 'tool_call' },
    },
    assessment: { result: ruleActive ? 'PROTECTED' : 'EXPOSED', reasons: ['gap'], surfaces: [{ name: 'tools', applicable: true, coverage: 'ENFORCED' }] },
    candidate: {
      possible: true,
      id: 'cand-1',
      explanation: 'Hold untrusted tool calls.',
      expected_action: 'require_approval',
      confidence: 'high',
      assumptions: [],
      conflicts: [],
      rule: { id: 'ti-untrusted-instruction-execution', type: 'tool_call' },
    },
    replay: { status: 'INSUFFICIENT_REPLAY_DATA', reason: 'No usable history', operations_analysed: 0 },
  };
}
