import { describe, expect, it } from 'vitest';
import { dedupePolicyDoc, ensurePolicyDoc, mergePolicyWithoutDuplicates, safeParsePolicy } from './policy';

const doc = {
  default: 'block',
  defaults: { subprocess: 'require_approval' },
  require_approval: [{ type: 'webmcp.tool_registered' }],
  sanitise: [{ type: 'webmcp.tool_output_scanned' }],
  block: [{ command: { program: 'rm', flags_all: [['r'], ['f']] } }],
  warn: [],
  monitor: [],
  allow: [],
  budget_rules: [],
};

describe('policy document round-trip', () => {
  it('keeps keys the rules editor does not edit', () => {
    const out = dedupePolicyDoc(ensurePolicyDoc(JSON.parse(JSON.stringify(doc))));
    expect(out.default).toBe('block');
    expect(out.defaults).toEqual({ subprocess: 'require_approval' });
    expect(out.require_approval).toHaveLength(1);
    expect(out.sanitise).toHaveLength(1);
    expect(out.block[0].command.program).toBe('rm');
  });

  it('safeParsePolicy preserves defaults', () => {
    expect(safeParsePolicy(JSON.stringify(doc), ensurePolicyDoc({})).default).toBe('block');
  });

  it('merging a template keeps the live default', () => {
    const merged = mergePolicyWithoutDuplicates(ensurePolicyDoc(doc), ensurePolicyDoc({ default: 'allow', block: [{ tool: 'x' }] }));
    expect(merged.default).toBe('block');
    expect(merged.block).toHaveLength(2);
    expect(merged.require_approval).toHaveLength(1);
  });
});
