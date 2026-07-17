export function pageFromLocation(pathname: string) {
  if (pathname.includes('/ui/coverage-gaps')) return 'coverage';
  if (pathname.includes('/ui/web-shield')) return 'webshield';
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
