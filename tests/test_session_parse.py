from varden_monitor.session import parse_session_argv


def test_parse_empty():
    assert parse_session_argv([]) == (".", False, None, "guarded")


def test_parse_dir():
    assert parse_session_argv(["/tmp"]) == ("/tmp", False, None, "guarded")


def test_parse_passive():
    assert parse_session_argv(["--passive", "proj"]) == ("proj", True, None, "observe")


def test_parse_strict():
    assert parse_session_argv(["--strict", ".", "--", "python", "agent.py"]) == (
        ".",
        False,
        ["python", "agent.py"],
        "strict",
    )


def test_parse_dash_command():
    assert parse_session_argv([".", "--", "cursor", "."]) == (".", False, ["cursor", "."], "guarded")


def test_parse_implied_command():
    assert parse_session_argv([".", "cursor", "."]) == (".", False, ["cursor", "."], "guarded")
