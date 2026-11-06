import { useState } from 'react';
import type { AuthorityGraph, GraphNode } from './types';

function nodeId(node: GraphNode): string {
  return String(node.node_id || node.id || '');
}

export function AuthorityGraph({ graph }: { graph: AuthorityGraph | undefined }) {
  const [selected, setSelected] = useState<string>('');
  if (!graph?.present) {
    return <p className="muted">No live authority graph was recorded for this run.</p>;
  }
  const hazard = new Set(graph.hazard_node_ids || []);
  const nodes = (graph.graph?.nodes || []).filter((node) => hazard.has(nodeId(node)));
  const edges = (graph.graph?.edges || []).filter((edge) => {
    const src = String(edge.src || edge.source || '');
    const dst = String(edge.dst || edge.target || '');
    return hazard.has(src) && hazard.has(dst);
  });
  const current = nodes.find((node) => nodeId(node) === selected);
  return (
    <div>
      <p className="muted">{graph.note}</p>
      {graph.analysis_incomplete ? <p className="verdict" data-kind="INCONCLUSIVE">Reachability search incomplete{graph.incompleteness_reason ? `: ${graph.incompleteness_reason}` : ''}</p> : null}
      {nodes.length === 0 ? <p>The engine recorded a graph and no hazardous-path node. That is not a claim that no hazard exists.</p> : null}
      <svg className="graph" viewBox={`0 0 640 ${Math.max(160, nodes.length * 48)}`} role="img" aria-label="Authority graph from the predictive engine">
        {nodes.map((node, index) => {
          const id = nodeId(node);
          const y = 28 + index * 48;
          return (
            <g key={id} onClick={() => setSelected(id)} style={{ cursor: 'pointer' }}>
              <rect x="16" y={y - 16} width="608" height="36" rx="4" fill={id === selected ? '#2a3332' : '#232220'} stroke={node.confirmed ? '#7ec8c3' : '#e0a15a'} />
              <text x="28" y={y + 4} fill="#ece7df" fontSize="13">{node.label || id}</text>
            </g>
          );
        })}
      </svg>
      <p className="muted">{edges.length} edge{edges.length === 1 ? '' : 's'} connect the highlighted nodes. Potential reachability is not a policy decision and not a completed action.</p>
      {current ? (
        <p className="mono">
          {nodeId(current)} · {current.lifecycle || current.state || 'unknown'} · {current.confirmed ? 'confirmed' : 'potential'}
        </p>
      ) : <p className="muted">Select a node to read its engine identifier and lifecycle.</p>}
      <ul>
        {(graph.findings || []).slice(0, 6).map((finding) => (
          <li key={`${finding.pattern}-${finding.path?.display || ''}`}>
            <span className="mono">{finding.pattern}</span>
            <div className="muted">{finding.path?.display || (finding.path?.nodes || []).join(' → ')}</div>
          </li>
        ))}
      </ul>
    </div>
  );
}
