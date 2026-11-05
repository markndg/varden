"""Local gauntlet server. Decisions come from scenario runs, not from fixtures."""
# ruff: noqa: E402

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from demos.security_gauntlet_loader import load_runner

runner = load_runner()
RUNS: dict[str, dict] = {}

app = FastAPI(title="Varden security gauntlet", docs_url=None, redoc_url=None)
DIST = Path(__file__).resolve().parent / "frontend" / "dist"


@app.get("/api/capabilities")
def capabilities():
    matrix = ROOT / "CAPABILITY_MATRIX.md"
    return {
        "checkout": runner.git_commit(),
        "version": runner.varden_version(),
        "os_enforcement_in_this_tree": False,
        "matrix_path": "CAPABILITY_MATRIX.md",
        "matrix_present": matrix.is_file(),
        "scenarios": list(runner.SCENARIOS),
    }


@app.get("/api/scenarios")
def scenarios():
    return {
        "scenarios": [
            {"id": "prompt-injection", "title": "Prompt injection and authority escalation"},
            {"id": "predictive-authority", "title": "Predictive Authority"},
            {"id": "mandatory-enforcement", "title": "Mandatory enforcement"},
            {"id": "auditable-evidence", "title": "Auditable evidence"},
            {"id": "coverage-gap", "title": "Honest failure and coverage gaps"},
        ]
    }


@app.post("/api/scenarios/{scenario_id}/run")
def run(scenario_id: str):
    try:
        record = runner.run_scenario(scenario_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="unknown scenario") from None
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"execution error: {exc.__class__.__name__}") from exc
    RUNS[record["run_id"]] = record
    return record


@app.get("/api/runs/{run_id}")
def get_run(run_id: str):
    record = RUNS.get(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="unknown run")
    return record


@app.get("/api/runs/{run_id}/evidence.json")
def evidence(run_id: str):
    record = RUNS.get(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="unknown run")
    return JSONResponse(record)


@app.get("/api/runs/{run_id}/report.html", response_class=HTMLResponse)
def report(run_id: str):
    record = RUNS.get(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="unknown run")
    return HTMLResponse(runner.render_html(record))


if DIST.is_dir():
    app.mount("/", StaticFiles(directory=str(DIST), html=True), name="ui")


def main() -> None:
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")


if __name__ == "__main__":
    main()
