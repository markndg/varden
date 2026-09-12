import { describe, expect, it } from 'vitest';
import { eventIdFromSearch, hasPredictiveAnalysis, predictiveDeepLink } from './routing';

describe('predictive deep-link routing', () => {
  it('parses stable event_id from search', () => {
    expect(eventIdFromSearch('?event_id=42')).toBe(42);
    expect(eventIdFromSearch('?event_id=0')).toBe(null);
    expect(eventIdFromSearch('?event_id=abc')).toBe(null);
    expect(eventIdFromSearch('')).toBe(null);
  });

  it('builds canonical predictive URL', () => {
    expect(predictiveDeepLink(17)).toBe('/ui/predictive?event_id=17');
  });

  it('detects predictive metadata including ALLOW', () => {
    expect(hasPredictiveAnalysis({ has_predictive: true })).toBe(true);
    expect(
      hasPredictiveAnalysis({
        action: { metadata: { predictive_authority: { mode: 'observe', final_decision: 'allow' } } },
      }),
    ).toBe(true);
    expect(hasPredictiveAnalysis({ action: { metadata: {} } })).toBe(false);
  });
});
