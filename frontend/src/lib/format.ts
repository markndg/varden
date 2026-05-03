export function classNames(...parts: Array<string | false | null | undefined>) {
  return parts.filter(Boolean).join(' ');
}

export function fmtTs(ts?: number) {
  if (ts === undefined || ts === null || Number.isNaN(Number(ts))) return '—';
  return new Date(ts * 1000).toLocaleString();
}

export function fmtNum(v?: number | null, digits = 0) {
  if (v === undefined || v === null || Number.isNaN(v)) return '0';
  return Number(v).toFixed(digits);
}

export function toDateTimeLocalValue(ts?: number | null) {
  if (ts === undefined || ts === null || Number.isNaN(Number(ts))) return '';
  const dt = new Date(ts * 1000);
  const pad = (v: number) => String(v).padStart(2, '0');
  return `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())}T${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}`;
}

export function fromDateTimeLocalValue(value?: string) {
  if (!value) return null;
  const ts = Date.parse(value);
  return Number.isFinite(ts) ? Math.floor(ts / 1000) : null;
}

export function latencyValueFromPoint(point: any): number | null {
  const value = point?.avg_latency_ms ?? point?.average_latency_ms ?? point?.latency_ms ?? point?.value_ms ?? point?.value ?? point?.avg ?? null;
  const num = Number(value);
  return Number.isFinite(num) ? num : null;
}

export function averageLatencyFromPoints(points: any[]): number | null {
  const vals = (points || []).map(latencyValueFromPoint).filter((v): v is number => v !== null);
  if (!vals.length) return null;
  return vals.reduce((a, b) => a + b, 0) / vals.length;
}
