from __future__ import annotations

import asyncio
import functools
import inspect
import types
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

from varden import current_guard
from varden_sdk.sdk import GuardResult, VardenBlockedError, VardenGuard, _json_safe

try:
    from langchain_core.callbacks import BaseCallbackHandler as _LangChainBaseCallbackHandler
except Exception:  # pragma: no cover - optional dependency
    _LangChainBaseCallbackHandler = object


@dataclass
class ProtectedLangChainConfig:
    agent_name: str = 'langchain-agent'
    workflow_id: str | None = None
    framework: str = 'langchain'
    metadata: dict[str, Any] = field(default_factory=dict)


class VardenToolWrapper:
    """Proxy wrapper for LangChain tools.

    This is useful when you want a dedicated wrapper object. For most drop-in
    integrations, prefer `protect_tools(...)`, which instruments the tool
    instances in place so they keep their original LangChain type identity.
    """

    def __init__(
        self,
        inner_tool: Any,
        *,
        guard: VardenGuard | None = None,
        agent_name: str = 'langchain-agent',
        workflow_id: str | None = None,
        framework: str = 'langchain',
        extra_metadata: dict[str, Any] | None = None,
    ):
        self.inner_tool = inner_tool
        self.guard = guard or current_guard()
        self.agent_name = agent_name
        self.workflow_id = workflow_id
        self.framework = framework
        self.extra_metadata = dict(extra_metadata or {})

        self.name = getattr(inner_tool, 'name', inner_tool.__class__.__name__)
        self.description = getattr(inner_tool, 'description', getattr(inner_tool, '__doc__', '') or '')
        self.args_schema = getattr(inner_tool, 'args_schema', None)
        self.return_direct = getattr(inner_tool, 'return_direct', False)
        self.tags = list(getattr(inner_tool, 'tags', []) or [])
        self.metadata = dict(getattr(inner_tool, 'metadata', {}) or {})

    def __getattr__(self, item: str) -> Any:
        return getattr(self.inner_tool, item)

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        tool = instrument_tool(
            self.inner_tool,
            guard=self.guard,
            agent_name=self.agent_name,
            workflow_id=self.workflow_id,
            framework=self.framework,
            extra_metadata=self.extra_metadata,
        )
        if hasattr(tool, 'invoke'):
            return tool.invoke(input, config=config, **kwargs)
        if hasattr(tool, 'run'):
            return tool.run(input, **kwargs)
        return tool(input, **kwargs)

    async def ainvoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        tool = instrument_tool(
            self.inner_tool,
            guard=self.guard,
            agent_name=self.agent_name,
            workflow_id=self.workflow_id,
            framework=self.framework,
            extra_metadata=self.extra_metadata,
        )
        if hasattr(tool, 'ainvoke'):
            return await tool.ainvoke(input, config=config, **kwargs)
        return await asyncio.to_thread(self.invoke, input, config=config, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        tool = instrument_tool(
            self.inner_tool,
            guard=self.guard,
            agent_name=self.agent_name,
            workflow_id=self.workflow_id,
            framework=self.framework,
            extra_metadata=self.extra_metadata,
        )
        if callable(tool):
            return tool(*args, **kwargs)
        return tool.run(*args, **kwargs)


class VardenCallbackHandler(_LangChainBaseCallbackHandler):
    def __init__(
        self,
        guard: VardenGuard | None = None,
        *,
        agent_name: str = 'langchain-agent',
        workflow_id: str | None = None,
        framework: str = 'langchain',
    ):
        super().__init__()
        self.guard = guard or current_guard()
        self.agent_name = agent_name
        self.workflow_id = workflow_id or str(uuid.uuid4())
        self.framework = framework

    @property
    def always_verbose(self) -> bool:  # pragma: no cover - compatibility shim
        return True

    def _run_key(self, run_id: Any) -> str:
        return str(run_id) if run_id is not None else str(uuid.uuid4())

    def _emit(self, kind: str, body: dict[str, Any], *, name: str) -> None:
        effective_guard = self.guard or current_guard()
        if not effective_guard:
            return
        payload = {
            'event_kind': kind,
            'framework': self.framework,
            **body,
        }
        try:
            effective_guard.guarded_action(
                type='workflow_event',
                tool=name,
                args=payload,
                payload=payload,
                agent_name=self.agent_name,
                workflow_id=self.workflow_id,
                metadata={'framework': self.framework, 'execution_surface': 'langchain-callback'},
            )
        except VardenBlockedError:
            return

    def on_chain_start(self, serialized: dict[str, Any], inputs: dict[str, Any], *, run_id: Any = None, parent_run_id: Any = None, **kwargs: Any) -> None:
        self._emit('chain_start', {'serialized': serialized, 'inputs': inputs, 'run_id': self._run_key(run_id), 'parent_run_id': self._run_key(parent_run_id) if parent_run_id else None}, name=serialized.get('name') or 'langchain.chain')

    def on_chain_end(self, outputs: dict[str, Any], *, run_id: Any = None, parent_run_id: Any = None, **kwargs: Any) -> None:
        self._emit('chain_end', {'outputs': outputs, 'run_id': self._run_key(run_id), 'parent_run_id': self._run_key(parent_run_id) if parent_run_id else None}, name='langchain.chain')

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, *, run_id: Any = None, parent_run_id: Any = None, **kwargs: Any) -> None:
        self._emit('tool_start', {'serialized': serialized, 'input': input_str, 'run_id': self._run_key(run_id), 'parent_run_id': self._run_key(parent_run_id) if parent_run_id else None}, name=serialized.get('name') or 'langchain.tool')

    def on_tool_end(self, output: Any, *, run_id: Any = None, parent_run_id: Any = None, **kwargs: Any) -> None:
        self._emit('tool_end', {'output': _json_safe(output), 'run_id': self._run_key(run_id), 'parent_run_id': self._run_key(parent_run_id) if parent_run_id else None}, name='langchain.tool')

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], *, run_id: Any = None, parent_run_id: Any = None, **kwargs: Any) -> None:
        self._emit('llm_start', {'serialized': serialized, 'prompts': prompts, 'run_id': self._run_key(run_id), 'parent_run_id': self._run_key(parent_run_id) if parent_run_id else None}, name=serialized.get('name') or 'langchain.llm')

    def on_llm_end(self, response: Any, *, run_id: Any = None, parent_run_id: Any = None, **kwargs: Any) -> None:
        self._emit('llm_end', {'response': _json_safe(response), 'run_id': self._run_key(run_id), 'parent_run_id': self._run_key(parent_run_id) if parent_run_id else None}, name='langchain.llm')

    def on_chain_error(self, error: BaseException, *, run_id: Any = None, parent_run_id: Any = None, **kwargs: Any) -> None:
        self._emit('chain_error', {'error': str(error), 'run_id': self._run_key(run_id), 'parent_run_id': self._run_key(parent_run_id) if parent_run_id else None}, name='langchain.chain')


def _tool_payload(tool: Any, *, args: tuple[Any, ...], kwargs: dict[str, Any], config: Any = None) -> dict[str, Any]:
    input_value = None
    if len(args) == 1 and not kwargs:
        input_value = args[0]
    elif args or kwargs:
        input_value = {'args': list(args), 'kwargs': kwargs}
    return {
        'tool_name': getattr(tool, 'name', tool.__class__.__name__),
        'tool_description': getattr(tool, 'description', getattr(tool, '__doc__', '') or ''),
        'input': _json_safe(input_value),
        'args': _json_safe(list(args)),
        'kwargs': _json_safe(kwargs),
        'config': _json_safe(config),
    }


def _guard_tool_call(tool: Any, *, guard: VardenGuard | None, agent_name: str, workflow_id: str | None, framework: str, extra_metadata: dict[str, Any] | None, payload: dict[str, Any]) -> GuardResult | None:
    effective_guard = guard or current_guard()
    if not effective_guard:
        return None
    return effective_guard.guarded_action(
        type='tool_call',
        tool=getattr(tool, 'name', tool.__class__.__name__),
        args=payload,
        payload=payload,
        agent_name=agent_name,
        workflow_id=workflow_id,
        metadata={
            'framework': framework,
            'execution_surface': 'langchain-tool',
            **dict(getattr(tool, 'metadata', {}) or {}),
            **dict(extra_metadata or {}),
        },
    )


def _record_tool_result(guard: VardenGuard | None, result: GuardResult | None, *, input_payload: dict[str, Any], output_payload: Any = None, error: str | None = None) -> None:
    effective_guard = guard or current_guard()
    if not effective_guard or not result:
        return
    effective_guard.record_result(
        action=result.action,
        decision=result.decision,
        input_payload=input_payload,
        output_payload=_json_safe(output_payload),
        error=error,
    )


def _maybe_block(guard: VardenGuard | None, result: GuardResult | None, tool_name: str) -> None:
    effective_guard = guard or current_guard()
    if result and result.blocked and effective_guard and effective_guard.mode == 'enforce':
        raise VardenBlockedError(f'LangChain tool {tool_name} blocked', result.decision)


def instrument_tool(
    tool: Any,
    *,
    guard: VardenGuard | None = None,
    agent_name: str = 'langchain-agent',
    workflow_id: str | None = None,
    framework: str = 'langchain',
    extra_metadata: dict[str, Any] | None = None,
) -> Any:
    if getattr(tool, '__varden_langchain_protected__', False):
        return tool

    originals: dict[str, Any] = {}

    def wrap_sync(method_name: str):
        if not hasattr(tool, method_name):
            return
        original = getattr(tool, method_name)
        if not callable(original):
            return
        originals[method_name] = original

        @functools.wraps(original)
        def wrapped(*args: Any, **kwargs: Any):
            config = kwargs.get('config') if method_name in {'invoke', 'ainvoke'} else None
            payload = _tool_payload(tool, args=args, kwargs=kwargs, config=config)
            result = _guard_tool_call(tool, guard=guard, agent_name=agent_name, workflow_id=workflow_id, framework=framework, extra_metadata=extra_metadata, payload=payload)
            _maybe_block(guard, result, getattr(tool, 'name', tool.__class__.__name__))
            try:
                value = original(*args, **kwargs)
                _record_tool_result(guard, result, input_payload=payload, output_payload=value)
                return value
            except Exception as exc:
                _record_tool_result(guard, result, input_payload=payload, error=str(exc))
                raise

        setattr(tool, method_name, types.MethodType(wrapped.__func__ if hasattr(wrapped, '__func__') else wrapped, tool) if inspect.ismethod(original) else wrapped)

    def wrap_async(method_name: str):
        if not hasattr(tool, method_name):
            return
        original = getattr(tool, method_name)
        if not callable(original):
            return
        originals[method_name] = original

        @functools.wraps(original)
        async def wrapped(*args: Any, **kwargs: Any):
            config = kwargs.get('config') if method_name in {'invoke', 'ainvoke'} else None
            payload = _tool_payload(tool, args=args, kwargs=kwargs, config=config)
            result = _guard_tool_call(tool, guard=guard, agent_name=agent_name, workflow_id=workflow_id, framework=framework, extra_metadata=extra_metadata, payload=payload)
            _maybe_block(guard, result, getattr(tool, 'name', tool.__class__.__name__))
            try:
                value = await original(*args, **kwargs)
                _record_tool_result(guard, result, input_payload=payload, output_payload=value)
                return value
            except Exception as exc:
                _record_tool_result(guard, result, input_payload=payload, error=str(exc))
                raise

        setattr(tool, method_name, types.MethodType(wrapped, tool) if inspect.ismethod(original) else wrapped)

    if hasattr(tool, 'invoke'):
        original_invoke = getattr(tool, 'invoke')
        if inspect.iscoroutinefunction(original_invoke):
            wrap_async('invoke')
        else:
            wrap_sync('invoke')
    if hasattr(tool, 'run'):
        original_run = getattr(tool, 'run')
        if inspect.iscoroutinefunction(original_run):
            wrap_async('run')
        else:
            wrap_sync('run')
    if hasattr(tool, 'ainvoke'):
        wrap_async('ainvoke')
    if hasattr(tool, 'arun'):
        wrap_async('arun')

    setattr(tool, '__varden_langchain_originals__', originals)
    setattr(tool, '__varden_langchain_protected__', True)
    return tool


def protect_tools(
    tools: Iterable[Any],
    *,
    guard: VardenGuard | None = None,
    agent_name: str = 'langchain-agent',
    workflow_id: str | None = None,
    framework: str = 'langchain',
    extra_metadata: dict[str, Any] | None = None,
) -> list[Any]:
    return [
        instrument_tool(
            tool,
            guard=guard,
            agent_name=agent_name,
            workflow_id=workflow_id,
            framework=framework,
            extra_metadata=extra_metadata,
        )
        for tool in tools
    ]


def protect_agent(
    agent: Any,
    *,
    tool_attribute_names: tuple[str, ...] = ('tools', '_tools'),
    guard: VardenGuard | None = None,
    agent_name: str = 'langchain-agent',
    workflow_id: str | None = None,
    framework: str = 'langchain',
    extra_metadata: dict[str, Any] | None = None,
) -> Any:
    for attr in tool_attribute_names:
        if hasattr(agent, attr):
            existing = getattr(agent, attr)
            if existing:
                setattr(
                    agent,
                    attr,
                    protect_tools(
                        existing,
                        guard=guard,
                        agent_name=agent_name,
                        workflow_id=workflow_id,
                        framework=framework,
                        extra_metadata=extra_metadata,
                    ),
                )
                break
    callbacks = list(getattr(agent, 'callbacks', []) or [])
    callbacks.append(VardenCallbackHandler(guard=guard, agent_name=agent_name, workflow_id=workflow_id, framework=framework))
    try:
        agent.callbacks = callbacks
    except Exception:
        pass
    return agent


def create_protected_agent(
    *,
    tools: Iterable[Any],
    guard: VardenGuard | None = None,
    agent_name: str = 'langchain-agent',
    workflow_id: str | None = None,
    framework: str = 'langchain',
    extra_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    workflow_id = workflow_id or str(uuid.uuid4())
    wrapped_tools = protect_tools(
        tools,
        guard=guard,
        agent_name=agent_name,
        workflow_id=workflow_id,
        framework=framework,
        extra_metadata=extra_metadata,
    )
    callback = VardenCallbackHandler(
        guard=guard,
        agent_name=agent_name,
        workflow_id=workflow_id,
        framework=framework,
    )
    return {
        'tools': wrapped_tools,
        'callbacks': [callback],
        'workflow_id': workflow_id,
        'agent_name': agent_name,
        'framework': framework,
    }
