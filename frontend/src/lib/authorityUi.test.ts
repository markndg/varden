import { describe, expect, it } from 'vitest';
import {
  blockNodeIsClean,
  decisionLabel,
  decisionTone,
  effectiveDecision,
  findingChips,
  findingLabel,
  incidentCountVsFindings,
  kindLabel,
  pathPreviewText,
  severityTone,
  shouldShowInvestigation,
  trustBoundaryLabel,
  trustLabel,
  type Incident,
} from './authorityUi';

describe('authorityUi labels', () => {
  it('humanises finding names with fallbacks', () => {
    expect(findingLabel('confused_deputy')).toBe('Confused deputy');
    expect(findingLabel({ type: 'delegation_violation' })).toBe('Missing delegated authority');
    expect(findingLabel({ type: 'x', label: 'Custom label' })).toBe('Custom label');
  });

  it('maps decision tones and kind labels', () => {
    expect(decisionLabel('blocked')).toBe('BLOCKED');
    expect(decisionTone('blocked')).toBe('danger');
    expect(decisionLabel('sanitised')).toBe('SANITISED · ALLOWED');
    expect(severityTone('critical')).toBe('danger');
    expect(trustLabel('untrusted')).toBe('UNTRUSTED');
    expect(kindLabel('mcp_server')).toBe('MCP SERVER');
    expect(kindLabel('tool_result')).toBe('TOOL RESULT');
    expect(kindLabel('enforcement')).toBe('ENFORCEMENT');
    expect(kindLabel('block')).toBe('BLOCKED');
    expect(trustBoundaryLabel('untrusted_input')).toBe('UNTRUSTED INPUT');
  });

  it('collapses finding chips', () => {
    const chips = findingChips([
      { type: 'confused_deputy', label: 'Confused deputy' },
      { type: 'authority_escalation', label: 'Authority escalation' },
      { type: 'delegation_violation', label: 'Missing delegated authority' },
      { type: 'untrusted_to_privileged', label: 'Untrusted source attempted privileged action' },
    ], 3);
    expect(chips.visible).toHaveLength(3);
    expect(chips.extra).toBe(1);
  });
});

describe('shared path projection', () => {
  it('prefers backend path_index over raw node labels', () => {
    const incident: Incident = {
      id: 'evt-1',
      attack_path: [
        { kind: 'tool_result', label: 'search.example' },
        { kind: 'mcp_server', label: 'search.example' },
        { kind: 'agent', label: 'demo-agent' },
        { kind: 'enforcement', label: 'VARDEN BLOCKED' },
      ],
      attack_path_preview: ['search.example / Search Web', 'demo-agent', 'BLOCKED'],
      path_index: {
        text: 'search.example / Search Web → demo-agent → notes.txt → BLOCKED',
        route: ['search.example / Search Web', 'demo-agent', 'notes.txt', 'BLOCKED'],
      },
    };
    expect(pathPreviewText(incident)).toBe('search.example / Search Web → demo-agent → notes.txt → BLOCKED');
    expect(pathPreviewText(incident)).not.toContain('search.example → search.example');
  });

  it('uses display_decision for sanitised allowed actions', () => {
    expect(effectiveDecision({ decision: 'allowed', display_decision: 'sanitised' })).toBe('sanitised');
    expect(decisionLabel('sanitised')).toContain('SANITISED');
  });

  it('keeps Overview investigation closed until a story is opened', () => {
    expect(shouldShowInvestigation('overview', null, false)).toBe(false);
    expect(shouldShowInvestigation('overview', 'evt-1', false)).toBe(false);
    expect(shouldShowInvestigation('overview', 'evt-1', true)).toBe(true);
    expect(shouldShowInvestigation('incidents', 'evt-1', false)).toBe(true);
    expect(shouldShowInvestigation('paths', 'evt-1', false)).toBe(true);
  });
});

describe('incident grouping and block semantics', () => {
  it('counts one incident for four findings and keeps block node clean', () => {
    const incidents: Incident[] = [{
      id: 'evt-1',
      decision: 'blocked',
      severity: 'critical',
      finding_count: 4,
      findings: [
        { type: 'confused_deputy', label: 'Confused deputy' },
        { type: 'authority_escalation', label: 'Authority escalation' },
        { type: 'delegation_violation', label: 'Missing delegated authority' },
        { type: 'untrusted_to_privileged', label: 'Untrusted source attempted privileged action' },
      ],
      attack_path: [
        { kind: 'tool_result', label: 'search.example', trust: 'untrusted', edge_to_next: 'influenced' },
        { kind: 'agent', label: 'agent', trust: 'delegated', edge_to_next: 'attempted' },
        { kind: 'mcp_server', label: 'crm.internal', edge_to_next: 'called' },
        { kind: 'tool', label: 'Admin delete user', capability: 'privileged', edge_to_next: 'blocked before' },
        { kind: 'enforcement', label: 'VARDEN BLOCKED', trust: null, sensitivity: null },
      ],
      path_index: {
        text: 'search.example / Search Web → demo-agent → crm.internal / Delete User → BLOCKED',
      },
    }];
    const counts = incidentCountVsFindings(incidents);
    expect(counts.incidents).toBe(1);
    expect(counts.findings).toBe(4);
    expect(pathPreviewText(incidents[0])).toContain('BLOCKED');
    expect(incidents[0].attack_path?.some((n) => n.kind === 'mcp_server')).toBe(true);
    expect(blockNodeIsClean(incidents[0].attack_path?.find((n) => n.kind === 'enforcement'))).toBe(true);
    expect(blockNodeIsClean({ kind: 'enforcement', trust: 'hostile' })).toBe(false);
  });
});
