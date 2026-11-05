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

1. Say what is in this checkout: Varden 1.1.0 policy, provenance, and Predictive Authority. Operating-system mandatory enforcement is not in this tree.
2. Run **Prompt injection**. The summary is allowed. The export tool is blocked and the local sink hash does not change. The baseline write, with no Varden call, does change a file. The sink is local and synthetic.
3. Run **Predictive Authority**. Point at the external-post step with the control enabled, and at the same step with it left off. A hazardous path is reachability evidence, not a claim that the agent would have continued.
4. Run **Mandatory enforcement**. The guarded write stops. The unguarded `open().write()` completes. The OS row is `UNSUPPORTED`.
5. Open the HTML assessment from **Auditable evidence**. The export does not raise the verdict above the run that produced it.
6. Run **Coverage gap** last. The file changes. The verdict is not prevention. Say what an operator would have to deploy before that write is inside a boundary.

## Tests

```bash
python -m pytest -q tests/security_gauntlet
```

Playwright smoke runs only when the UI has been built and Playwright is installed. Otherwise that test skips.
