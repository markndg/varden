from __future__ import annotations

import os
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import varden
from varden_langchain import protect_tools

try:
    from langchain_core.tools import StructuredTool
except Exception:  # optional dependency fallback for local demos
    StructuredTool = None


@dataclass
class DemoTool:
    name: str
    description: str
    func: Callable[[Any], Any]
    metadata: dict[str, Any] = field(default_factory=dict)

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        payload = input
        if kwargs:
            payload = {'input': input, 'kwargs': kwargs}
        return self.func(payload)


def configure_guard(app_name: str) -> None:
    varden.protect(
        base_url=os.getenv('VARDEN_BASE_URL', 'http://127.0.0.1:8000'),
        api_key=os.getenv('VARDEN_API_KEY', 'admin-demo-key'),
        app_name=app_name,
    )


def make_langchain_tool(name: str, description: str, fn: Callable[[Any], Any]) -> Any:
    if StructuredTool is not None:
        return StructuredTool.from_function(func=fn, name=name, description=description)
    return DemoTool(name=name, description=description, func=fn)


def protect_demo_tools(*, agent_name: str, tools: list[Any]) -> dict[str, Any]:
    workflow_id = str(uuid.uuid4())
    protected_tools = protect_tools(
        tools,
        agent_name=agent_name,
        workflow_id=workflow_id,
        extra_metadata={'demo': True, 'integration': 'langchain'},
    )
    return {'tools': protected_tools, 'agent_name': agent_name, 'workflow_id': workflow_id}


def print_banner(title: str) -> None:
    print('\n' + '=' * 72)
    print(title)
    print('=' * 72)
