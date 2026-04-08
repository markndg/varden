from demos import allowed_safe_agent, blocked_tool_agent, flagged_data_agent, database_sql_agent


def test_demo_modules_expose_run():
    assert callable(blocked_tool_agent.run)
    assert callable(flagged_data_agent.run)
    assert callable(allowed_safe_agent.run)
    assert callable(database_sql_agent.run)


def test_demo_defaults_are_localhost():
    assert blocked_tool_agent.BASE_URL.startswith('http://127.0.0.1:8000')
    assert flagged_data_agent.API_KEY == 'admin-demo-key'
    assert allowed_safe_agent.AGENT_NAME == 'allowed-demo-agent'
    assert database_sql_agent.SQL_TOOL == 'sql.query'
