from varden.classification import ClassifierEngine
from varden.db import init_db
from varden.policy import PolicyEngine
from varden.models import Action


def test_classifier_flags_dangerous_sql():
    payload = {"sql": "DROP TABLE customers;"}
    result = ClassifierEngine().classify(payload)
    assert result["sql_query"] is True
    assert result["sql_dangerous"] is True
    assert result["sql_multi_statement"] is False


def test_classifier_flags_suspect_read_sql():
    payload = {"sql": "SELECT * FROM customers"}
    result = ClassifierEngine().classify(payload)
    assert result["sql_select_star"] is True
    assert result["sql_sensitive_table"] is True
    assert result["sql_missing_limit"] is True


def test_templates_include_database_pack(tmp_path):
    engine = PolicyEngine(str(tmp_path / 'varden.db'))
    templates = engine.templates()
    assert 'block_dangerous_database_operations' in templates
    assert 'warn_suspect_sql_operations' in templates


def test_default_policy_blocks_unbounded_sql_write(tmp_path):
    import json
    policy = json.loads((tmp_path.parent / 'policy.json').read_text()) if False else None
    engine = PolicyEngine(str(tmp_path / 'varden.db'))
    import pathlib, json as _json
    repo_policy = _json.loads(pathlib.Path(__file__).resolve().parents[1].joinpath('policy.json').read_text(encoding='utf-8'))
    engine.update_policy(repo_policy)
    action = Action(
        type='tool_call',
        tool='sql.query',
        args={'kwargs': {'sql': 'DELETE FROM customers'}},
        classifiers=ClassifierEngine().classify({'sql': 'DELETE FROM customers'})
    )
    decision = engine.evaluate(action)
    assert decision.action == 'block'


def test_default_policy_warns_sensitive_select(tmp_path):
    engine = PolicyEngine(str(tmp_path / 'varden.db'))
    import pathlib, json as _json
    repo_policy = _json.loads(pathlib.Path(__file__).resolve().parents[1].joinpath('policy.json').read_text(encoding='utf-8'))
    engine.update_policy(repo_policy)
    sql = 'SELECT * FROM customers'
    action = Action(
        type='tool_call',
        tool='sql.query',
        args={'kwargs': {'sql': sql}},
        classifiers=ClassifierEngine().classify({'sql': sql})
    )
    decision = engine.evaluate(action)
    assert decision.action == 'warn'


def test_empty_operator_values_do_not_match_everything(tmp_path):
    engine = PolicyEngine(str(tmp_path / 'varden.db'))
    engine.update_policy({"block": [{"field:route_target": {"contains": ""}}], "warn": [], "monitor": [], "allow": []})
    decision = engine.evaluate(Action(type='tool_call', tool='safe.tool', route_target='cloud'))
    assert decision.action == 'allow'


def test_invalid_numeric_operator_fails_closed(tmp_path):
    engine = PolicyEngine(str(tmp_path / 'varden.db'))
    engine.update_policy({"block": [{"field:risk_score": {"gte": "not-a-number"}}], "warn": [], "monitor": [], "allow": []})
    decision = engine.evaluate(Action(type='tool_call', tool='safe.tool', risk_score=25))
    assert decision.action == 'allow'


def test_blank_simple_rule_fields_are_wildcards(tmp_path):
    engine = PolicyEngine(str(tmp_path / 'varden.db'))
    engine.update_policy({"block": [], "warn": [], "monitor": [], "allow": [{"type": "", "tool": "safe.tool"}]})
    decision = engine.evaluate(Action(type='tool_call', tool='safe.tool'))
    assert decision.action == 'allow'
    assert decision.matched_rule is not None


def test_metadata_only_rules_do_not_match_or_validate(tmp_path):
    engine = PolicyEngine(str(tmp_path / 'varden.db'))
    candidate = {"block": [{"title": "catch all by accident", "enabled": True}], "warn": [], "monitor": [], "allow": []}
    assert engine.validate(candidate)["valid"] is False
    engine.update_policy(candidate)
    decision = engine.evaluate(Action(type='tool_call', tool='safe.tool'))
    assert decision.action == 'allow'
    assert decision.matched_rule is None


def test_multiple_numeric_operators_are_all_required(tmp_path):
    engine = PolicyEngine(str(tmp_path / 'varden.db'))
    engine.update_policy({"block": [{"field:risk_score": {"gte": 10, "lte": 20}}], "warn": [], "monitor": [], "allow": []})
    assert engine.evaluate(Action(type='tool_call', tool='safe.tool', risk_score=15)).action == 'block'
    assert engine.evaluate(Action(type='tool_call', tool='safe.tool', risk_score=25)).action == 'allow'


def test_publish_missing_version_does_not_archive_current(tmp_path):
    db_path = str(tmp_path / 'varden.db')
    init_db(db_path)
    engine = PolicyEngine(db_path)
    version_id = engine.snapshot('current', status='published')
    result = engine.publish(version_id + 100)
    assert result["published_version"] is None
    versions = engine.list_versions()
    assert versions[0]["id"] == version_id
    assert versions[0]["status"] == "published"
