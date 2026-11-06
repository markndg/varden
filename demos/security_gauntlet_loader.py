"""Import the hyphenated gauntlet package without installing it."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_DIR = Path(__file__).resolve().parent / "security-gauntlet" / "runner"
_PACKAGE = "gauntlet_runner"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    module.__package__ = _PACKAGE
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_runner():
    if _PACKAGE not in sys.modules:
        package = _load(_PACKAGE, _DIR / "__init__.py")
        package.__path__ = [str(_DIR)]
        for name in ("schema", "session", "os_probe", "report", "scenarios"):
            _load(f"{_PACKAGE}.{name}", _DIR / f"{name}.py")
    scenarios = sys.modules[f"{_PACKAGE}.scenarios"]
    schema = sys.modules[f"{_PACKAGE}.schema"]
    report = sys.modules[f"{_PACKAGE}.report"]
    session = sys.modules[f"{_PACKAGE}.session"]
    os_probe = sys.modules[f"{_PACKAGE}.os_probe"]
    return type(
        "Runner",
        (),
        {
            "run_scenario": scenarios.run_scenario,
            "SCENARIOS": scenarios.SCENARIOS,
            "classify": schema.classify,
            "aggregate": schema.aggregate,
            "seal": schema.seal,
            "build_outcomes": schema.build_outcomes,
            "render_html": report.render_html,
            "render_json": report.render_json,
            "platform_status": os_probe.platform_status,
            "resolve_supervisor": os_probe.resolve_supervisor,
            "interpret_contained": os_probe.interpret_contained,
            "enforcement_capabilities": os_probe.enforcement_capabilities,
            "run_os_probe": os_probe.run_os_probe,
            "git_commit": session.git_commit,
            "varden_version": session.varden_version,
        },
    )
