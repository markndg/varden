# Varden security gauntlet

A local demonstration of released Varden behaviour. It is not a tour of the unmerged monitoring-integrity branch. Read `CAPABILITY_MATRIX.md` before presenting it.

## Run

From the repository root, with the project virtualenv active:

```bash
python demos/security-gauntlet/serve.py
```

Build the buyer UI once, then open the same server:

```bash
cd demos/security-gauntlet/frontend
npm install
npm run build
cd ../../..
python demos/security-gauntlet/serve.py
```

Open http://127.0.0.1:8765/

`npm run dev` in `frontend/` proxies `/api` to that server for UI work.

The server creates a disposable SQLite database and policy file per run and deletes them when the run finishes. It does not edit the repository policy or require root.

## What a run actually does

1. Start Varden's ASGI app in-process.
2. Bootstrap a dev API key.
3. `POST /sdk/guard` for each mediated action.
4. Write a disposable file only when the returned decision is not `block`, `deny`, or `require_approval`.
5. Hash the file before and after.
6. Classify the result. `VERIFIED_PREVENTED` is refused without that independent check.

## Five-minute buyer script

Start on Predictive Authority. Each scenario is one real execution of the baseline and the protected workflow. Walk the seven steps on the page. The three lines — baseline, protected claim, overall — are the same text as the JSON and HTML exports.

1. Legitimate task. The agent is asked to investigate issue 42 from repository context.
2. Hazardous path. Select a node. The nodes are the live authority graph after `/sdk/guard`. A path is reachability, not a completed action.
3. Baseline. Predictive Authority is off. The local sink is written.
4. Control. The protected half of the same run sets enforce mode and `VARDEN_PA_DEPLOYMENT=single_worker`.
5. Protected execution. The first `require_approval` is the intervention. The external-post file is not written when that decision is preventing.
6. Observed difference. Read the baseline line and the protected line separately. Do not quote only one of them.
7. Evidence. Open the guard reason, the event id, and the before/after hashes. Then open the HTML assessment.

If time remains, run prompt injection and point at the allowed summary as a different protected step from the prevented export. Run mandatory enforcement and leave the overall line at `UNSUPPORTED` unless a contained Seatbelt probe was actually executed. Run the coverage gap last. The file changes.

Operating-system enforcement is not in this checkout. To probe the unmerged supervisor on macOS, set `VARDEN_INTEGRITY_ROOT` to a checkout of `feature/monitoring-integrity` and run mandatory enforcement again. Linux and Windows stay unverified. A same-user write outside the profile is not prevention.

## Tests

```bash
python -m pytest -q tests/security_gauntlet
cd demos/security-gauntlet/frontend && npm test && npm run build
```

Playwright smoke runs when the UI has been built and Playwright Chromium is installed. CI installs Chromium. A missing browser skips the test locally.
