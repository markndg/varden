# VARDEN-UI-STABILITY-001

Branch: `feature/threat-intelligence`. Not committed.

## Ctrl+C shutdown

### Root cause

The hang predates Threat Intelligence. `GET /stream/updates` is an unbounded server-sent stream, and the dashboard keeps it open for the life of the page. Uvicorn's shutdown waits for open connections before it runs the FastAPI lifespan. With `timeout_graceful_shutdown` left unset, that wait does not end. Lifespan cleanup (the alert worker, and the intelligence poller when it is enabled) never starts.

The `CancelledError` at `starlette/responses.py` inside `anyio.create_task_group()` is what appears when that still-open `StreamingResponse` is finally cancelled. It is a symptom of the connection that never finished.

### Files changed

- `varden/api.py` — `GracefulServer` closes application streams before Uvicorn waits on sockets, and sets a 5 second graceful backstop. `KeyboardInterrupt` from the asyncio runner is caught only after that shutdown has returned, so the process exits without a traceback.
- `varden/app_factory.py` — `EventStreamBroker.close()` wakes every subscriber. The stream generator returns on that sentinel. Lifespan shutdown closes the broker, then stops the intelligence scheduler and the alert worker.
- `varden/alerts.py` — the alert worker waits on an event instead of `time.sleep`, so `stop()` does not sit for a full poll interval.

`CancelledError` is not swallowed inside request handlers. The stream generator still lets cancellation propagate. The entrypoint catch is the process exit after Uvicorn has already logged application shutdown.

### SIGINT test result

`tests/test_graceful_shutdown.py` starts `python -m varden.api`, waits for `/health/live`, sends one SIGINT, and fails the test if the process has to be killed.

Passed:

- no clients
- an active `/health` request
- an open `/stream/updates` response
- Threat Intelligence disabled
- Threat Intelligence enabled
- Threat Intelligence enabled with a short poll interval, so a source fetch can be in progress

### Time to terminate

Each case must finish within 12 seconds of SIGINT. The six-process run, including cold starts, finished in 7.49 seconds. A second run of the open-stream case and the in-flight poll case finished in 4.80 seconds, including a 1.5 second wait before the signal. Exit code was 0.

### Traceback

Eliminated. The tests fail if stderr contains `Traceback (most recent call last)`, `CancelledError`, or `starlette/responses.py`. None of those appeared. Server logs show `Application shutdown complete` and `Finished server process`.

## Predictive Authority

### Root cause of the escaped node

Node cards were HTML inside an SVG `foreignObject`, and each card icon was a nested `<svg>`. That inner SVG is not positioned in the graph's viewBox. Chromium paints and hit-tests it in page coordinates, which is how a node for `chat_message:github.issue` (title "GitHub input", state CONFIRMED) appeared over the left navigation. The tooltip was that node's `<title>`.

The first column was also placed 4 units outside the viewBox (`pad` 70, node half-width 74), and the SVG's default overflow is visible, so even a correctly positioned card could paint past the panel.

### Rendering and coordinate fix

- Node labels are SVG `<text>` in the same coordinate system as the node rectangle. There is no `foreignObject` and no nested SVG.
- Column inset is 96, so a 148×56 node stays inside the 980×460 viewBox. Nodes whose boxes fall outside that box are not mounted, so they have no hit target.
- A `clipPath` on the graph group clips edges, markers, and badges to the viewBox.
- The panel is `overflow: hidden`. The hover tooltip is an element inside that panel, clamped to the panel box. It is not portaled onto the navigation.
- The sidebar stacking order is above the main column, so a graph hit target cannot win over a nav control.

### Layout

The existing page is unchanged in structure. The graph panel has a visible frame and a taller viewport. Node titles and subtitles use higher-contrast fills. Hazard nodes keep the red stroke, and their titles pick up the hazard color. Edges and arrowheads are lighter so the secondary graph stays readable while the hazardous trajectory stays the strong red path. The inspector stretches with the graph column. Below 980px the graph and inspector stack.

### Browser geometry

`tests/browser/test_ui_stability.py::test_predictive_graph_stays_inside_the_viewport` passed against the built UI:

- demo loads and mounts graph nodes
- every `[data-testid^="pa-node-"]` box is inside `[data-testid="graph-panel"]` and does not intersect `.sidebar`
- hovering the first sidebar item does not show the graph tooltip
- hovering a node shows `[data-testid="pa-tooltip"]` inside the panel and not over the sidebar
- wheel, mode changes, and Fit do not create an escaped node
- Hide inspector removes `[data-testid="evidence-inspector"]`; showing it restores the panel
- at a 1000px viewport the panel stays inside the window and nodes stay inside the panel

### Screenshots

- `data/reports/ui-stability/predictive-desktop.png`
- `data/reports/ui-stability/predictive-narrow.png`

The hazardous path (`~/.aws/credentials` → `http.write.external`, interrupted at REQUIRE APPROVAL) stays in the graph. No node sits on the navigation.

## Coverage Gaps

### Root cause

The zeros were a real empty classification, not a failed request and not a chart that failed to mount. The page clusters `overview.recent_events` and recent trace events in the browser. The default window is 7 days. An event with a matched enforcing decision is not a gap. With no recent uncovered events, the counters are 0.

The main region looked blank because the empty card had `min-height: 0` and the copy ("No coverage gaps in this view", "No uncovered tool activity") did not say why the count was zero. Zero gaps was easy to read as "coverage is complete."

Two data-path holes made some real gaps invisible even when events existed:

- The dashboard summary omitted `coverage_status`, action type, method, and whether provenance was present, so PARTIAL and NOT_ROUTED never reached the page.
- Any matched label, including a monitor decision, was treated as covered.

### Backend and frontend

Both. `varden/stores.py` now includes `action_type`, `method`, `coverage_status`, and `provenance_present` on recent events. `frontend/src/lib/coverageGaps.ts` classifies them. The page renders that result.

Classification:

- no applicable policy → uncovered
- PARTIAL or OBSERVATIONAL → weak, not complete enforcement
- NOT_ROUTED, UNCOVERED, or UNSUPPORTED → uncovered
- missing provenance → uncovered, including when a rule matched
- block, require approval, sanitise, or warn with a matched rule and provenance → covered
- a matched rule that is not one of those decisions → weak
- repeated events with the same type, tool, method, domain, classifiers, and reasons → one cluster

### Were the zero counts legitimate?

Yes, when the loaded window has no observed events, or every observed action in that window has complete enforcement. They are not evidence that unobserved surfaces are protected. A fresh database shows "No observed events" and says the zero is not proof of coverage. Logging one allowed `gap-fixture-tool` action with no matching policy produces one uncovered cluster.

The page still mounts when overview telemetry has not loaded, and says coverage telemetry is unavailable instead of leaving the content area empty.

### Data path

Runtime event → event store → `recent_events` (now including surface status and provenance) → dashboard overview → `CoverageGapsPage` → `classifyCoverage` → cluster list or an explained empty state.

Empty reasons, each with its own copy: telemetry unavailable, analysis failed, no observed events, agent filter with no observations, time window excluding events, filters hiding clusters, and no uncovered events inside an otherwise populated window.

### Regression tests

`frontend/src/lib/coverageGaps.test.ts` covers the eight fixtures: no policy, PARTIAL, NOT_ROUTED, complete enforcement, missing provenance, one cluster for two events, an agent with no observations, and filters that hide valid gaps. All passed.

`tests/browser/test_ui_stability.py::test_coverage_empty_then_populated` passed. Screenshots:

- `data/reports/ui-stability/coverage-empty.png`
- `data/reports/ui-stability/coverage-populated.png`

## Test summary

| Suite | Start | Final | Failed | Skipped |
| --- | --- | --- | --- | --- |
| pytest, full tree including browser | 823 non-browser, plus 9 Playwright smoke | 840 | 0 | 0 |
| Vitest | 36 | 46 | 0 | 0 |
| `tsc --noEmit` | clean | clean | 0 | — |
| Vite build | succeeded | succeeded (`app.js` 460.51 kB, `app.css` 69.15 kB) | 0 | — |

The full pytest run was 840 passed and 2 existing warnings in 110 seconds. That includes the 9 Playwright smoke tests, 6 SIGINT tests, and 2 new browser geometry/coverage tests. Vitest is 46 passed across 7 files (10 new cases: 9 coverage, 1 layout inset).

## Verdict

READY
