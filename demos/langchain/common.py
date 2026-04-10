from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable

import sentinel
from sentinel_langchain import create_protected_agent


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
    os.environ.setdefault('SENTINEL_BASE_URL', 'http://127.0.0.1:8000')
    os.environ.setdefault('SENTINEL_API_KEY', 'admin-demo-key')
    sentinel.protect_from_env(auto_instrument=False, app_name=app_name)


def make_demo_bundle(*, agent_name: str, tools: list[DemoTool]):
    return create_protected_agent(
        tools=tools,
        agent_name=agent_name,
        extra_metadata={'demo': True, 'integration': 'langchain'},
    )


def print_banner(title: str) -> None:
    print('\n' + '=' * 72)
    print(title)
    print('=' * 72)
