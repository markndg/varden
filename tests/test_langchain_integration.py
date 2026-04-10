from __future__ import annotations

import uuid

import pytest

import sentinel
from sentinel.sdk import GuardResult
from sentinel_langchain import SentinelCallbackHandler, create_protected_agent, protect_agent, protect_tools


class FakeTool:
    def __init__(self, name: str, description: str = ''):
        self.name = name
        self.description = description or name
        self.metadata = {'tool_kind': 'demo'}

    def invoke(self, input, config=None, **kwargs):
        return {'tool': self.name, 'input': input, 'config': config}


class FakeAgent:
    def __init__(self, tools):
        self.tools = tools
        self.callbacks = []


class DummyGuard:
    def __init__(self):
        self.mode = 'enforce'
        self.guard_calls = []
        self.result_calls = []

    def guarded_action(self, **kwargs):
        self.guard_calls.append(kwargs)
        tool = kwargs.get('tool')
        action = 'allow'
        if tool == 'external_http':
            action = 'warn'
        if tool == 'dangerous_sql':
            action = 'block'
        return GuardResult(decision={'action': action}, action=kwargs, event_id=len(self.guard_calls))

    def record_result(self, **kwargs):
        self.result_calls.append(kwargs)
        return {'ok': True}


def test_protect_tools_blocks_and_warns():
    guard = DummyGuard()
    protected = protect_tools([
        FakeTool('safe_lookup'),
        FakeTool('external_http'),
        FakeTool('dangerous_sql'),
    ], guard=guard, agent_name='agent-x')
    assert protected[0].invoke({'q': 'hello'})['tool'] == 'safe_lookup'
    assert protected[1].invoke({'url': 'https://example.com'})['tool'] == 'external_http'
    with pytest.raises(sentinel.SentinelBlockedError):
        protected[2].invoke('DROP TABLE customers;')
    assert any(call['tool'] == 'external_http' and call['metadata']['execution_surface'] == 'langchain-tool' for call in guard.guard_calls)
    assert any(call['decision']['action'] == 'warn' for call in guard.result_calls)


def test_create_protected_agent_returns_tools_and_callbacks():
    bundle = create_protected_agent(tools=[FakeTool('lookup')], agent_name='bundle-agent')
    assert len(bundle['tools']) == 1
    assert len(bundle['callbacks']) == 1
    assert bundle['agent_name'] == 'bundle-agent'
    assert getattr(bundle['tools'][0], '__sentinel_langchain_protected__', False) is True


def test_callback_handler_emits_workflow_events():
    guard = DummyGuard()
    handler = SentinelCallbackHandler(guard=guard, agent_name='lc-agent', workflow_id='wf-test')
    run_id = uuid.uuid4()
    handler.on_chain_start({'name': 'agent-executor'}, {'input': 'hello'}, run_id=run_id)
    handler.on_tool_start({'name': 'external_http'}, 'fetch me', run_id=uuid.uuid4(), parent_run_id=run_id)
    assert any(call['type'] == 'workflow_event' for call in guard.guard_calls)
    assert any(call['tool'] == 'external_http' for call in guard.guard_calls)


def test_protect_agent_instruments_existing_tools_and_callbacks():
    guard = DummyGuard()
    agent = FakeAgent([FakeTool('safe_lookup')])
    protected_agent = protect_agent(agent, guard=guard, agent_name='agent-y')
    assert protected_agent is agent
    assert len(agent.callbacks) == 1
    assert agent.tools[0].invoke({'q': 'hello'})['tool'] == 'safe_lookup'
    assert guard.guard_calls[0]['tool'] == 'safe_lookup'
