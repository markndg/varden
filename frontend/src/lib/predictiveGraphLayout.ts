/**
 * Predictive Authority graph presentation helpers.
 * Layout/grouping/labeling only — never invents security facts.
 */

export type GraphNode = {
  id?: string;
  node_id?: string;
  label?: string;
  kind?: string;
  node_type?: string;
  state?: string;
  confirmed?: boolean;
  trustDomain?: string;
  sensitive?: boolean;
  metadata?: Record<string, any>;
};

export type GraphEdge = {
  id?: string;
  source?: string;
  target?: string;
  src?: string;
  dst?: string;
  relationship?: string;
  kind?: string;
  state?: string;
  evidenceKind?: string;
  evidence?: Record<string, any>;
  label?: string;
};

export type GraphMode = 'before' | 'after' | 'delta' | 'trajectory';

export type NodeColumn =
  | 'source'
  | 'action'
  | 'resource'
  | 'capability'
  | 'sink'
  | 'enforcement';

export type DisplayLabel = {
  title: string;
  subtitle: string;
  state: string;
  icon: string;
};

export type CapabilityGroup = {
  id: string;
  title: string;
  memberIds: string[];
  potentialCount: number;
  confirmedCount: number;
};

export type LayoutPoint = { x: number; y: number };

export function nid(n: GraphNode | string) {
  if (typeof n === 'string') return n;
  return String(n.id || n.node_id || '');
}

export function eid(e: GraphEdge) {
  return String(e.id || `${e.source || e.src}|${e.target || e.dst}`);
}

export function esrc(e: GraphEdge) {
  return String(e.source || e.src || '');
}

export function edst(e: GraphEdge) {
  return String(e.target || e.dst || '');
}

export function nodeType(n: GraphNode) {
  return String(n.node_type || n.kind || '');
}

export function nodeState(n: GraphNode) {
  return String(n.state || (n.confirmed ? 'confirmed' : 'potential')).toLowerCase();
}

export function isPotentialNode(n: GraphNode) {
  const s = nodeState(n);
  return s === 'potential' || n.confirmed === false;
}

export function isEnforcementNode(n: GraphNode) {
  const t = nodeType(n);
  return t.includes('enforcement') || /require_approval|block|warn/i.test(String(n.label || ''));
}

export function columnFor(n: GraphNode): NodeColumn {
  const t = nodeType(n);
  const id = nid(n).toLowerCase();
  const label = String(n.label || '').toLowerCase();
  if (isEnforcementNode(n)) return 'enforcement';
  if (t.includes('untrusted') || t.includes('provenance') || t.includes('chat') || id.includes('untrusted')) return 'source';
  if (t === 'action' || t === 'mcp_tool' || t === 'mcp_server' || id.startsWith('action:')) return 'action';
  if (
    t.includes('credential') ||
    t.includes('secret') ||
    t === 'filesystem_path' ||
    t.includes('resource') ||
    id.startsWith('res:')
  ) {
    // Network sinks are consequences, not credentials.
    if (t.includes('network') || label.includes('evil.') || id.includes('network_origin')) return 'sink';
    return 'resource';
  }
  if (t.includes('network') || t === 'sink' || t === 'sanitisation_boundary') return 'sink';
  if (t === 'capability' || id.startsWith('cap:') || id.startsWith('cap.potential:')) {
    // External write capabilities behave as sinks in the story.
    if (/http\.write|external|exfil/i.test(label) || /http\.write|external/.test(id)) return 'sink';
    return 'capability';
  }
  return 'capability';
}

export function humanizeLabel(n: GraphNode): DisplayLabel {
  const raw = String(n.label || nid(n));
  const t = nodeType(n);
  const state = nodeState(n).toUpperCase();
  let title = raw;
  let subtitle = raw;
  let icon = 'node';

  if (t.includes('untrusted') || raw.startsWith('chat_message')) {
    title = raw.includes('github') ? 'GitHub input' : 'Untrusted input';
    subtitle = raw.replace(/^chat_message:/, '');
    icon = 'message';
  } else if (t === 'action' || raw.startsWith('filesystem.read') || raw.startsWith('http.write') || raw.startsWith('tool_call')) {
    if (raw.includes('credentials') || raw.includes('.aws')) title = 'Read AWS credentials';
    else if (raw.includes('config')) title = 'Read config';
    else if (raw.includes('http.write') || raw.includes('evil')) title = 'HTTP write';
    else if (raw.includes('ingest')) title = 'Ingest issue';
    else if (raw.startsWith('tool_call:')) title = raw.replace('tool_call:', '');
    else title = raw.replace(/^filesystem\.read\s*/, 'Read ').replace(/^http\.write\s*/, 'Write ');
    subtitle = raw.length > 42 ? `${raw.slice(0, 40)}…` : raw;
    icon = raw.includes('http') ? 'globe' : 'file';
  } else if (t.includes('credential') || raw.includes('credential.aws') || nid(n).includes('credential')) {
    title = 'AWS credentials';
    subtitle = 'credential.aws';
    icon = 'key';
  } else if (t === 'filesystem_path') {
    title = raw.includes('.aws') ? '~/.aws/credentials' : raw;
    subtitle = 'filesystem path';
    icon = 'file';
  } else if (t.includes('network') || /evil\.|external/.test(raw)) {
    title = raw.includes('evil') ? 'External host' : raw;
    subtitle = raw;
    icon = 'globe';
  } else if (t === 'capability' || raw.includes('.')) {
    const name = raw.replace(/^cap\.(potential:)?/, '').replace(/^cap:/, '');
    if (name.startsWith('aws.')) {
      const parts = name.split('.');
      title = `${parts[1]?.toUpperCase() || 'AWS'} ${parts.slice(2).join(' ') || parts[1] || ''}`.trim();
      subtitle = name;
      icon = 'cloud';
    } else if (name.includes('filesystem.read')) {
      title = name.includes('secret') ? 'Read secrets' : 'Read workspace';
      subtitle = name;
      icon = 'file';
    } else if (name.includes('http.write')) {
      title = 'External write';
      subtitle = name;
      icon = 'globe';
    } else if (name.includes('credential')) {
      title = 'Credential authority';
      subtitle = name;
      icon = 'key';
    } else {
      title = name;
      subtitle = name;
      icon = 'cap';
    }
  } else if (t === 'sanitisation_boundary') {
    title = 'Sanitisation';
    subtitle = raw;
    icon = 'filter';
  }

  // Keep titles readable; never empty.
  if (!title.trim()) title = raw.slice(0, 28) || 'node';
  if (title.length > 28) title = `${title.slice(0, 26)}…`;
  if (subtitle.length > 36) subtitle = `${subtitle.slice(0, 34)}…`;

  return { title, subtitle, state, icon };
}

export function capabilityGroupKey(n: GraphNode): string | null {
  if (columnFor(n) !== 'capability') return null;
  const label = String(n.label || nid(n));
  const m = label.match(/\b(aws|gcp|azure)\./i);
  if (m) return m[1].toLowerCase();
  return null;
}

export function buildCapabilityGroups(nodes: GraphNode[]): CapabilityGroup[] {
  const buckets = new Map<string, GraphNode[]>();
  for (const n of nodes) {
    const key = capabilityGroupKey(n);
    if (!key) continue;
    (buckets.get(key) || buckets.set(key, []).get(key)!).push(n);
  }
  const groups: CapabilityGroup[] = [];
  for (const [key, members] of buckets) {
    if (members.length < 3) continue;
    groups.push({
      id: `group:${key}`,
      title: `${key.toUpperCase()} authority`,
      memberIds: members.map(nid).sort(),
      potentialCount: members.filter(isPotentialNode).length,
      confirmedCount: members.filter((n) => !isPotentialNode(n)).length,
    });
  }
  return groups.sort((a, b) => a.title.localeCompare(b.title));
}

const COLUMN_ORDER: NodeColumn[] = ['source', 'action', 'resource', 'capability', 'sink', 'enforcement'];

export function columnIndex(col: NodeColumn) {
  return COLUMN_ORDER.indexOf(col);
}

/** Stable layered layout. Positions are centers. */
export function computeStableLayout(
  nodes: GraphNode[],
  width: number,
  height: number,
  opts?: { groupsCollapsed?: Record<string, boolean>; groups?: CapabilityGroup[] },
): Record<string, LayoutPoint> {
  const groups = opts?.groups || buildCapabilityGroups(nodes);
  const collapsed = opts?.groupsCollapsed || {};
  const positions: Record<string, LayoutPoint> = {};
  const byCol: Record<NodeColumn, GraphNode[]> = {
    source: [],
    action: [],
    resource: [],
    capability: [],
    sink: [],
    enforcement: [],
  };

  const groupedIds = new Set<string>();
  for (const g of groups) {
    if (collapsed[g.id]) {
      for (const id of g.memberIds) groupedIds.add(id);
    }
  }

  for (const n of nodes) {
    const id = nid(n);
    if (groupedIds.has(id)) continue;
    byCol[columnFor(n)].push(n);
  }

  const padX = 70;
  const usableW = Math.max(200, width - padX * 2);
  const activeCols = COLUMN_ORDER.filter((c) => c === 'enforcement' || byCol[c].length || groups.some((g) => collapsed[g.id] && c === 'capability'));
  const colCount = Math.max(1, activeCols.length);

  const placeColumn = (col: NodeColumn, items: Array<{ id: string; sort: string }>, x: number) => {
    const sorted = items.slice().sort((a, b) => a.sort.localeCompare(b.sort));
    const n = Math.max(1, sorted.length);
    const top = 56;
    const bottom = height - 48;
    sorted.forEach((item, i) => {
      const y = top + ((i + 0.5) / n) * (bottom - top);
      positions[item.id] = { x, y };
    });
  };

  activeCols.forEach((col, li) => {
    const x = padX + (li / Math.max(1, colCount - 1 || 1)) * usableW;
    if (col === 'capability') {
      const items: Array<{ id: string; sort: string }> = byCol.capability.map((n) => ({
        id: nid(n),
        sort: `${capabilityGroupKey(n) || 'z'}:${String(n.label || nid(n))}`,
      }));
      for (const g of groups) {
        if (collapsed[g.id]) {
          items.push({ id: g.id, sort: `0:${g.title}` });
        }
      }
      placeColumn(col, items, x);
    } else if (col !== 'enforcement') {
      placeColumn(
        col,
        byCol[col].map((n) => ({ id: nid(n), sort: String(n.label || nid(n)) })),
        x,
      );
    } else {
      positions['__gate__'] = { x, y: height / 2 };
    }
  });

  // Always reserve gate position on the far right for enforcement presentation.
  if (!positions['__gate__']) {
    positions['__gate__'] = { x: width - 70, y: height / 2 };
  }

  // Place collapsed group members near group center (hidden but stable for mode switches).
  for (const g of groups) {
    const anchor = positions[g.id];
    if (!anchor) continue;
    g.memberIds.forEach((id, i) => {
      if (!positions[id]) {
        positions[id] = { x: anchor.x, y: anchor.y + (i - g.memberIds.length / 2) * 4 };
      }
    });
  }

  return positions;
}

/** Orthogonal path with a single elbow (or straight if aligned). */
export function orthogonalPath(a: LayoutPoint, b: LayoutPoint, nodeHalfW = 58): string {
  const x1 = a.x + Math.min(nodeHalfW, Math.abs(b.x - a.x) * 0.25);
  const y1 = a.y;
  const x2 = b.x - Math.min(nodeHalfW, Math.abs(b.x - a.x) * 0.25);
  const y2 = b.y;
  if (Math.abs(y1 - y2) < 2) return `M ${x1} ${y1} L ${x2} ${y2}`;
  const midX = (x1 + x2) / 2;
  return `M ${x1} ${y1} H ${midX} V ${y2} H ${x2}`;
}

export function isEdgeOnPath(e: GraphEdge, pathNodes: Set<string>) {
  if (!pathNodes.size) return false;
  return pathNodes.has(esrc(e)) && pathNodes.has(edst(e));
}

export function nodeInBefore(n: GraphNode, before?: { capabilities?: string[]; confirmed?: string[]; potential?: string[] } | null) {
  const col = columnFor(n);
  // Provenance / actions / resources are observed context.
  if (col === 'source' || col === 'action' || col === 'resource') return true;
  if (isPotentialNode(n)) return false;
  if (!before) return true;
  const label = String(n.label || '');
  const confirmed = new Set(before.confirmed || []);
  if (confirmed.has(label)) return true;
  // Tolerate id/label mismatches for confirmed names.
  for (const c of confirmed) {
    if (label.endsWith(c) || c.endsWith(label) || nid(n).includes(c)) return true;
  }
  // Confirmed-looking sinks/capabilities not listed in before.confirmed are predicted outcomes.
  return false;
}

export function filterNodesForMode(
  nodes: GraphNode[],
  mode: GraphMode,
  opts: {
    before?: any;
    after?: any;
    pathNodes?: Set<string>;
    showPotential?: boolean;
    showContext?: boolean;
  },
): { visible: Set<string>; emphasis: Record<string, 'primary' | 'alt' | 'context' | 'hidden'> } {
  const emphasis: Record<string, 'primary' | 'alt' | 'context' | 'hidden'> = {};
  const visible = new Set<string>();
  const path = opts.pathNodes || new Set<string>();
  const showPotential = opts.showPotential !== false;
  const showContext = opts.showContext !== false;

  for (const n of nodes) {
    const id = nid(n);
    if (mode === 'before') {
      if (!nodeInBefore(n, opts.before) && columnFor(n) !== 'source' && columnFor(n) !== 'action' && columnFor(n) !== 'resource') {
        emphasis[id] = 'hidden';
        continue;
      }
      if (isPotentialNode(n)) {
        emphasis[id] = 'hidden';
        continue;
      }
      visible.add(id);
      emphasis[id] = 'primary';
      continue;
    }

    if (mode === 'delta') {
      const isNew = isPotentialNode(n) || (opts.after?.potential || []).includes(String(n.label || ''));
      const isBase = columnFor(n) === 'source' || columnFor(n) === 'action' || columnFor(n) === 'resource' || (!isPotentialNode(n) && columnFor(n) === 'capability');
      if (isNew) {
        visible.add(id);
        emphasis[id] = 'primary';
      } else if (isBase) {
        visible.add(id);
        emphasis[id] = 'context';
      } else if (showContext) {
        visible.add(id);
        emphasis[id] = 'context';
      } else {
        emphasis[id] = 'hidden';
      }
      continue;
    }

    if (mode === 'trajectory' && path.size) {
      if (path.has(id)) {
        visible.add(id);
        emphasis[id] = 'primary';
      } else if (showContext) {
        visible.add(id);
        emphasis[id] = 'context';
      } else {
        emphasis[id] = 'hidden';
      }
      continue;
    }

    // after / default
    if (!showPotential && isPotentialNode(n)) {
      emphasis[id] = 'hidden';
      continue;
    }
    visible.add(id);
    if (path.size && path.has(id)) emphasis[id] = 'primary';
    else if (path.size) emphasis[id] = showContext ? 'context' : 'alt';
    else emphasis[id] = isPotentialNode(n) ? 'alt' : 'primary';
  }

  return { visible, emphasis };
}

export function opacityForEmphasis(level: 'primary' | 'alt' | 'context' | 'hidden' | undefined, mode: GraphMode) {
  if (level === 'hidden') return 0;
  if (level === 'primary') return 1;
  if (level === 'alt') return mode === 'trajectory' ? 0.55 : 0.72;
  if (level === 'context') return mode === 'trajectory' ? 0.22 : 0.3;
  return 1;
}

export function decisionRank(action?: string) {
  const order: Record<string, number> = {
    allow: 0,
    monitor: 1,
    warn: 2,
    sanitise: 3,
    require_approval: 4,
    block: 5,
  };
  return order[String(action || 'allow')] ?? 0;
}

export function formatDecision(action?: string, mode?: string) {
  const a = String(action || '').replace(/_/g, ' ').toUpperCase();
  if (mode === 'observe' && decisionRank(action) >= decisionRank('require_approval')) {
    return `WOULD ${a}`;
  }
  return a;
}

export function pickPrimaryTrajectory(trajectories: any[]): any | null {
  if (!trajectories?.length) return null;
  const scored = trajectories.map((t, i) => {
    const nodes = t?.path?.nodes || [];
    const display = String(t?.path?.display || t?.description || '');
    let score = nodes.length * 10;
    if (/iam|privilege|escalat/i.test(display + (t?.pattern || ''))) score += 50;
    if (/exfil|external|s3\.write/i.test(display + (t?.pattern || ''))) score += 30;
    score -= i;
    return { t, score };
  });
  scored.sort((a, b) => b.score - a.score);
  return scored[0]?.t || trajectories[0];
}

export function evidenceCounts(pathOrEvent: any) {
  const edges = pathOrEvent?.path?.edges || pathOrEvent?.hazardous_paths || [];
  // Best-effort from findings list: not inventing evidence, only summarizing present fields.
  let confirmed = 0;
  let inferred = 0;
  let potential = 0;
  const walk = (obj: any) => {
    if (!obj || typeof obj !== 'object') return;
    const kind = String(obj.evidenceKind || obj.evidence?.kind || obj.state || '').toLowerCase();
    if (kind.includes('potential') || kind.includes('untrusted')) potential += 1;
    else if (kind.includes('infer') || kind.includes('derived')) inferred += 1;
    else if (kind.includes('observed') || kind.includes('confirmed') || kind.includes('configured')) confirmed += 1;
  };
  if (Array.isArray(edges)) edges.forEach(walk);
  return { confirmed, inferred, potential };
}
