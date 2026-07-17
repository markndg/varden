from __future__ import annotations

import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from varden.webshield.engine import scan_output, scan_registration
from varden.webshield.models import ScanContext, WebMCPToolDefinition
from varden.webshield.sanitize import sanitize_tool

# Arbitrary but bounded text: printable Unicode plus a deliberately adversarial
# slice including zero-width/bidi/control characters and surrogates-adjacent
# code points, since those are exactly the inputs the Unicode layer must
# survive without raising.
_ADVERSARIAL_CHARS = "\u200b\u200c\u200d\ufeff\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\x00\x01\x1f\ud7ff\ue000"

text_strategy = st.text(
    alphabet=st.one_of(
        st.characters(blacklist_categories=("Cs",), max_codepoint=0x2FFFF),
        st.sampled_from(_ADVERSARIAL_CHARS),
    ),
    max_size=400,
)

json_scalar = st.one_of(st.text(max_size=100), st.integers(), st.floats(allow_nan=False, allow_infinity=False), st.booleans(), st.none())


def json_value(children):
    return st.one_of(
        json_scalar,
        st.lists(children, max_size=5),
        st.dictionaries(st.text(min_size=1, max_size=20), children, max_size=5),
    )


json_strategy = st.recursive(json_scalar, json_value, max_leaves=25)

schema_strategy = st.recursive(
    st.dictionaries(st.sampled_from(["type", "description", "title", "default"]), st.text(max_size=50), max_size=3),
    lambda children: st.dictionaries(
        st.sampled_from(["type", "description", "title", "properties", "items", "default"]),
        st.one_of(st.text(max_size=50), st.dictionaries(st.text(min_size=1, max_size=10), children, max_size=4), children),
        max_size=4,
    ),
    max_leaves=15,
)


@given(name=text_strategy, description=text_strategy, title=st.one_of(st.none(), text_strategy))
@settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
def test_scan_registration_never_raises_on_arbitrary_text(name, description, title):
    tool = WebMCPToolDefinition(name=name[:200] or "t", description=description, title=title, owner_origin="https://fuzz.test")
    result = scan_registration(tool)
    assert isinstance(result.risk.score, int)
    assert 0 <= result.risk.score <= 100
    json.dumps(result.to_dict())  # must always be serialisable


@given(schema=schema_strategy)
@settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
def test_scan_registration_never_raises_on_arbitrary_schema(schema):
    tool = WebMCPToolDefinition(name="fuzz_tool", description="d", input_schema=schema, owner_origin="https://fuzz.test")
    result = scan_registration(tool)
    json.dumps(result.to_dict())


@given(text=text_strategy)
@settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
def test_scan_output_never_raises(text):
    findings, risk = scan_output(text, owner_origin="https://fuzz.test")
    assert 0 <= risk.score <= 100
    for f in findings:
        json.dumps(f.to_dict())


@given(name=text_strategy, description=text_strategy)
@settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
def test_sanitize_is_idempotent_on_arbitrary_text(name, description):
    tool = WebMCPToolDefinition(name=name[:200] or "t", description=description, owner_origin="https://fuzz.test")
    once = sanitize_tool(tool)
    twice = sanitize_tool(once.sanitized_tool)
    assert once.sanitized_tool.description == twice.sanitized_tool.description


@given(name=text_strategy, description=text_strategy)
@settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
def test_hashing_deterministic_and_repeatable(name, description):
    tool = WebMCPToolDefinition(name=name[:200] or "t", description=description, owner_origin="https://fuzz.test")
    first = tool.compute_hashes()
    second = tool.compute_hashes()
    assert first == second


@given(text=text_strategy)
@settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
def test_scan_registration_handles_large_values_without_exception(text):
    # Pad to exercise the oversized-metadata path deterministically.
    padded = (text or "x") * 200
    tool = WebMCPToolDefinition(name="t", description=padded[:50_000], owner_origin="https://fuzz.test")
    result = scan_registration(tool)
    json.dumps(result.to_dict())


@given(data=json_strategy)
@settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow])
def test_from_raw_never_raises_on_arbitrary_json_shapes(data):
    if not isinstance(data, dict):
        data = {"value": data}
    tool = WebMCPToolDefinition.from_raw(data, owner_origin="https://fuzz.test")
    scan_registration(tool)
