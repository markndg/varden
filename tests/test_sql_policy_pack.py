from sentinel.classification import ClassifierEngine
from sentinel.policy import PolicyEngine
from sentinel.models import Action


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
    engine = PolicyEngine(str(tmp_path / 'sentinel.db'))
    templates = engine.templates()
    assert 'block_dangerous_database_operations' in templates
    assert 'warn_suspect_sql_operations' in templates


def test_default_policy_blocks_unbounded_sql_write(tmp_path):
    import json
    policy = json.loads((tmp_path.parent / 'policy.json').read_text()) if False else None
    engine = PolicyEngine(str(tmp_path / 'sentinel.db'))
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
    engine = PolicyEngine(str(tmp_path / 'sentinel.db'))
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
