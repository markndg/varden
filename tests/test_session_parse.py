from varden_monitor.session import parse_session_argv


def test_parse_session_defaults():
    assert parse_session_argv([]) == (".", False, None)


def test_parse_session_dir_only():
    assert parse_session_argv(["/tmp"]) == ("/tmp", False, None)


def test_parse_session_passive():
    assert parse_session_argv(["--passive", "proj"]) == ("proj", True, None)


def test_parse_session_explicit_dash():
    assert parse_session_argv([".", "--", "cursor", "."]) == (".", False, ["cursor", "."])


def test_parse_session_implicit_command():
    assert parse_session_argv([".", "cursor", "."]) == (".", False, ["cursor", "."])
