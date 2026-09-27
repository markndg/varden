import { describe, expect, it } from 'vitest';
import {
  buildCapabilityGroups,
  columnFor,
  computeStableLayout,
  filterNodesForMode,
  formatDecision,
  humanizeLabel,
  orthogonalPath,
  pickPrimaryTrajectory,
} from './predictiveGraphLayout';

const demoNodes = [
  { id: 'src', label: 'chat_message:github.issue', node_type: 'untrusted_content', state: 'confirmed' },
  { id: 'act', label: 'filesystem.read config.json', node_type: 'action', state: 'confirmed' },
  { id: 'cred', label: 'credential.aws', node_type: 'credential', state: 'confirmed' },
  { id: 'c1', label: 'aws.s3.read', node_type: 'capability', state: 'potential' },
  { id: 'c2', label: 'aws.s3.write', node_type: 'capability', state: 'potential' },
  { id: 'c3', label: 'aws.iam.modify', node_type: 'capability', state: 'potential' },
  { id: 'c4', label: 'aws.iam.read', node_type: 'capability', state: 'potential' },
  { id: 'sink', label: 'http.write.external', node_type: 'capability', state: 'potential' },
];

describe('predictiveGraphLayout', () => {
  it('assigns layered security columns', () => {
    expect(columnFor(demoNodes[0])).toBe('source');
    expect(columnFor(demoNodes[1])).toBe('action');
    expect(columnFor(demoNodes[2])).toBe('resource');
    expect(columnFor(demoNodes[3])).toBe('capability');
    expect(columnFor(demoNodes[7])).toBe('sink');
  });

  it('keeps human labels readable without losing identity', () => {
    const label = humanizeLabel(demoNodes[3] as any);
    expect(label.title.length).toBeLessThanOrEqual(28);
    expect(label.subtitle).toContain('aws.s3.read');
    expect(label.state).toBe('POTENTIAL');
  });

  it('groups AWS capability fan-out', () => {
    const groups = buildCapabilityGroups(demoNodes as any);
    expect(groups.some((g) => g.id === 'group:aws')).toBe(true);
    expect(groups[0].memberIds.length).toBeGreaterThanOrEqual(3);
  });

  it('produces stable layered positions across modes', () => {
    const a = computeStableLayout(demoNodes as any, 900, 400);
    const b = computeStableLayout(demoNodes as any, 900, 400);
    expect(a.src).toEqual(b.src);
    expect(a.cred.x).toBeLessThan(a.c1.x);
    expect(a.src.x).toBeLessThan(a.act.x);
  });

  it('routes edges orthogonally', () => {
    const d = orthogonalPath({ x: 10, y: 10 }, { x: 200, y: 120 });
    expect(d.startsWith('M ')).toBe(true);
    expect(d.includes('H') || d.includes('V') || d.includes('L')).toBe(true);
  });

  it('hides future potential in before mode', () => {
    const { visible, emphasis } = filterNodesForMode(demoNodes as any, 'before', {
      before: { confirmed: ['credential.aws'], potential: ['aws.s3.read', 'http.write.external'] },
      showPotential: true,
      showContext: true,
    });
    expect(visible.has('src')).toBe(true);
    expect(visible.has('cred')).toBe(true);
    expect(emphasis.c1).toBe('hidden');
    expect(emphasis.sink).toBe('hidden');
  });

  it('marks predicted vs confirmed for after mode', () => {
    const { emphasis } = filterNodesForMode(demoNodes as any, 'after', { showPotential: true, showContext: true });
    expect(emphasis.c1).toBe('alt');
    expect(emphasis.cred).toBe('primary');
  });

  it('formats observe decisions as WOULD …', () => {
    expect(formatDecision('require_approval', 'observe')).toBe('WOULD REQUIRE APPROVAL');
    expect(formatDecision('require_approval', 'enforce')).toBe('REQUIRE APPROVAL');
  });

  it('picks a meaningful primary trajectory', () => {
    const primary = pickPrimaryTrajectory([
      { pattern: 'untrusted_to_sensitive_to_external', path: { nodes: ['a', 'b'], display: 'exfil' }, index: 0 },
      { pattern: 'untrusted_to_credential_to_privileged', path: { nodes: ['a', 'b', 'c'], display: 'iam privilege' }, index: 1 },
    ]);
    expect(primary.pattern).toContain('privileged');
  });
});
