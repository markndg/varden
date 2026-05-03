from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any
import time, uuid

@dataclass
class Action:
    type: str
    tool: str | None = None
    method: str | None = None
    url: str | None = None
    domain: str | None = None
    args: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    classifiers: dict[str, bool] = field(default_factory=dict)
    risk_score: int = 0
    risk_reasons: list[str] = field(default_factory=list)
    agent_name: str | None = None
    workflow_id: str | None = None
    parent_event_id: int | None = None
    trace_id: str | None = None
    route_target: str | None = None
    tenant_id: str | None = None
    def to_dict(self): return asdict(self)

@dataclass
class Decision:
    action: str
    reason: str
    matched_rule: dict[str, Any] | None = None
    effective_action: str | None = None
    route_target: str | None = None
    def to_dict(self): return asdict(self)

@dataclass
class EventRecord:
    timestamp: float
    action: dict[str, Any]
    decision: dict[str, Any]
    status: str
    input_payload: Any = None
    output_payload: Any = None
    error: str | None = None
    replayable: bool = False
    replay_key: str | None = None
    workflow_id: str | None = None
    agent_name: str | None = None
    parent_event_id: int | None = None
    trace_id: str | None = None
    tenant_id: str | None = None
    @classmethod
    def new(cls, **kwargs):
        if "timestamp" not in kwargs:
            kwargs["timestamp"] = time.time()
        return cls(**kwargs)
    def to_dict(self): return asdict(self)

@dataclass
class WorkflowSession:
    name: str
    workflow_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: float = field(default_factory=time.time)
    closed_at: float | None = None
    tenant_id: str | None = None
    status: str = "active"
    def to_dict(self): return asdict(self)
