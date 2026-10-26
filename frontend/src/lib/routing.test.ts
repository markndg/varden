import { describe, expect, it } from 'vitest';
import { eventIdFromSearch, hasPredictiveAnalysis, pageFromLocation, predictiveDeepLink, threatIntelligencePath, threatItemIdFromLocation } from './routing';

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

  it('routes threat intelligence list and investigation pages', () => {
    expect(pageFromLocation('/ui/threat-intelligence')).toBe('threat-intelligence');
    expect(threatItemIdFromLocation('/ui/threat-intelligence')).toBe(null);
    expect(threatItemIdFromLocation('/ui/threat-intelligence/atlas%3AAML.T0051')).toBe('atlas:AML.T0051');
    expect(threatIntelligencePath()).toBe('/ui/threat-intelligence');
    expect(threatIntelligencePath('atlas:AML.T0051')).toBe('/ui/threat-intelligence/atlas%3AAML.T0051');
  });
});
