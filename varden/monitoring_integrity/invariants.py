"""Machine-checkable monitoring-integrity invariants.

Each invariant is enforced only on the surfaces named here. A pass on one
surface is not a global guarantee.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class InvariantSpec:
    id: str
    summary: str
    definition: str
    surfaces: tuple[str, ...]
    trust: str
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "summary": self.summary,
            "definition": self.definition,
            "surfaces": list(self.surfaces),
            "trust": self.trust,
            "limitations": list(self.limitations),
        }


INVARIANTS: dict[str, InvariantSpec] = {
    "INV-001": InvariantSpec(
        id="INV-001",
        summary="A protected agent cannot downgrade its own required enforcement mode.",
        definition="mode_rank(proposed) < mode_rank(sealed) or fail_mode changes from closed to open, on a protected enforcement asset, without an independent approval.",
        surfaces=("filesystem", "environment", "http", "mcp", "subprocess"),
        trust="The sealed policy mode is the operator baseline. The agent process is not an authority over that mode.",
        limitations=(
            "Direct writes to CoverageRegistry in this interpreter are outside the interceptor.",
            "os.exec*, ctypes, and saved pre-patch references are not mediated.",
        ),
    ),
    "INV-002": InvariantSpec(
        id="INV-002",
        summary="A protected agent cannot disable mandatory security auditing through a covered execution surface.",
        definition="A mutating operation on a protected audit or logging asset is denied unless that operation is permitted or independently approved.",
        surfaces=("filesystem", "environment", "http", "mcp"),
        trust="Audit continuity is judged from the sealed asset identity, not from the agent's log statements.",
        limitations=("An audit store replaced outside every intercepted API is detected only on the next verification read.",),
    ),
    "INV-003": InvariantSpec(
        id="INV-003",
        summary="An agent cannot remove a required monitoring integration without independent authorisation.",
        definition="Unlink, disable, or replacement of a required monitoring integration is denied unless a single-use approval names that asset and INV-003.",
        surfaces=("filesystem", "http", "mcp", "subprocess"),
        trust="The integration asset is protected only when the operator marked it protected.",
        limitations=("A plugin removed by a package manager outside the intercepted subprocess API is not prevented.",),
    ),
    "INV-004": InvariantSpec(
        id="INV-004",
        summary="An agent cannot redirect mandatory security notifications to an unauthorised destination.",
        definition="A proposed notification destination must canonicalise to a member of the asset allowlist. An unreadable destination fails closed.",
        surfaces=("filesystem", "http", "environment"),
        trust="Allowlist entries are operator-sealed. Destination identity uses Varden URL canonicalisation.",
        limitations=("DNS rebinding after canonicalisation is not closed by URL identity alone.",),
    ),
    "INV-005": InvariantSpec(
        id="INV-005",
        summary="An agent cannot successfully claim full coverage when required coverage is missing or unverified.",
        definition="A write or publish of an attestation/coverage claim that asserts ENFORCED or full coverage is denied when live required coverage is not verified, or the attestation is stale.",
        surfaces=("filesystem", "http", "mcp"),
        trust="Coverage status comes from CoverageRegistry, not from agent metadata.",
        limitations=("Speech in a model response is not an enforcement surface. Only a mediated publish or write is blocked.",),
    ),
    "INV-006": InvariantSpec(
        id="INV-006",
        summary="A protected child workload cannot be treated as covered without an applicable enforcement boundary.",
        definition="When monitored child execution is required, a launch whose coverage is unknown or absent is denied at the launch boundary Varden controls. Partial coverage is not reported as verified.",
        surfaces=("subprocess",),
        trust="The parent interceptor sees the launch arguments. It does not see the child's later syscalls.",
        limitations=(
            "Descendants of an allowed child are not proven covered.",
            "os.exec*, os.spawn*, and ctypes process creation are not intercepted.",
        ),
    ),
    "INV-007": InvariantSpec(
        id="INV-007",
        summary="An agent cannot modify the policy that authorises its own sensitive actions unless an independent authority permits that change.",
        definition="A mutating operation on a protected policy asset by a protected agent is denied unless the approval issuer is not that agent and the approval names the asset, operation, and INV-007.",
        surfaces=("filesystem", "http", "mcp"),
        trust="Client metadata claiming an operator role is ignored.",
        limitations=("A control-plane process that evaluates with a trusted operator actor is a separate principal from the agent.",),
    ),
    "INV-008": InvariantSpec(
        id="INV-008",
        summary="An integrity-verification failure cannot silently transition a protected workflow into permissive execution.",
        definition="Missing, stale, mismatched, or unobservable mandatory evidence on a protected mutating operation yields UNKNOWN and, in guarded or strict mode with fail-closed, an enforced block. It never yields allow.",
        surfaces=("filesystem", "subprocess", "http", "mcp", "environment"),
        trust="Fail-open control-plane transport does not override a local sealed deny.",
        limitations=("If no interceptor is installed, the outcome is NOT_ENFORCEABLE and the side effect is not described as prevented.",),
    ),
}


def invariant_catalog(selected: tuple[str, ...] | list[str] | None = None) -> list[dict[str, Any]]:
    keys = list(selected) if selected else list(INVARIANTS)
    return [INVARIANTS[key].to_dict() for key in keys if key in INVARIANTS]
