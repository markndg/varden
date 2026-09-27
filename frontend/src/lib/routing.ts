export function pageFromLocation(pathname: string) {
  if (pathname.includes('/ui/coverage-gaps')) return 'coverage';
  if (pathname.includes('/ui/web-shield')) return 'webshield';
  if (pathname.includes('/ui/predictive')) return 'predictive';
  if (pathname.includes('/ui/authority')) return 'authority';
  if (pathname.includes('/ui/impact')) return 'impact';
  if (pathname.includes('/ui/rules')) return 'rules';
  if (/\/ui\/decision\/\d+/.test(pathname)) return 'decision';
  return 'overview';
}

export function ruleBucketFromSearch(search: string) {
  return new URLSearchParams(search).get('bucket') || '';
}

export function ruleFocusTokenFromSearch(search: string) {
  const params = new URLSearchParams(search);
  return params.get('token') || params.get('focus') || '';
}

export function ruleReturnToFromSearch(search: string) {
  return new URLSearchParams(search).get('returnTo') || '';
}

export function detailIdFromLocation(pathname: string) {
  const match = pathname.match(/\/ui\/decision\/(\d+)/);
  return match ? Number(match[1]) : null;
}

/** Stable audit event id for Predictive deep links: /ui/predictive?event_id=<id> */
export function eventIdFromSearch(search: string): number | null {
  const raw = new URLSearchParams(search).get('event_id');
  if (!raw) return null;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : null;
}

export function predictiveDeepLink(eventId: number): string {
  return `/ui/predictive?event_id=${encodeURIComponent(String(eventId))}`;
}

export function hasPredictiveAnalysis(source: any): boolean {
  if (!source) return false;
  if (source.has_predictive) return true;
  const meta =
    source?.action?.metadata?.predictive_authority ||
    source?.action_metadata?.predictive_authority ||
    source?.metadata?.predictive_authority ||
    source?.predictive_authority;
  return Boolean(meta && typeof meta === 'object' && Object.keys(meta).length);
}
