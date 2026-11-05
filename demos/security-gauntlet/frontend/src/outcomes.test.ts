import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { assuranceLines, scopeLines } from './types.ts';

describe('scope lines', () => {
  it('keeps an allowed baseline distinct from a prevented protected claim', () => {
    const lines = scopeLines({
      outcomes: {
        baseline: { scope: 'baseline', verdict: 'OBSERVED_ONLY', legs: ['baseline_without_varden'] },
        protected: { scope: 'protected', verdict: 'VERIFIED_PREVENTED', legs: ['legitimate_summary', 'untrusted_export'], claim_leg: 'untrusted_export' },
        overall: { scope: 'overall', verdict: 'VERIFIED_PREVENTED', legs: ['untrusted_export'], claim_leg: 'untrusted_export', excludes_baseline: true },
      },
    });
    assert.equal(lines.baseline, 'Baseline execution: OBSERVED_ONLY');
    assert.equal(lines.protected, 'Protected execution (untrusted_export): VERIFIED_PREVENTED');
    assert.equal(lines.overall, 'Overall scenario outcome: VERIFIED_PREVENTED');
    assert.notEqual(lines.baseline, lines.overall);
  });

  it('prints the three mandatory-enforcement results separately', () => {
    const lines = assuranceLines({
      sdk: { verdict: 'VERIFIED_PREVENTED', leg: 'sdk_guarded_write' },
      os_supervised: { verdict: 'VERIFIED_PREVENTED', leg: 'os_supervisor' },
      unsupervised_same_user: { verdict: 'OBSERVED_ONLY', leg: 'outside_profile_write' },
    });
    assert.deepEqual(lines, [
      'SDK-mediated protection: VERIFIED_PREVENTED',
      'OS-supervised process: VERIFIED_PREVENTED',
      'Unsupervised same-user process: OBSERVED_ONLY',
    ]);
  });
});
