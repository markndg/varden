# @varden/web-shield

Runtime governance and tool-surface security for browser agents. A small, framework-neutral
SDK that reports WebMCP tool registrations, invocations and outputs to a
[Varden](https://github.com/markndg/varden) server, and respects whatever policy decision comes back.

This SDK does not scan anything itself — all detection, risk scoring and policy evaluation happen
server-side (`varden/webshield`), the same engine used by `varden web-shield scan`, the attack lab,
and the browser extension. The SDK is the "first-party" integration path: because it runs as part
of the website's own code, it can genuinely withhold a registration/invocation/output when the
server says `block`, unlike a browser extension which can only observe and wrap what the platform
exposes.

See `docs/web-shield-sdk.md` in the main repository for the full usage guide, and
`docs/web-shield-limitations.md` for what this SDK does and does not guarantee.

## Install

This package is not yet published. From a source checkout:

```bash
cd sdks/js/web-shield
npm install
npm run build
```

Then reference `sdks/js/web-shield/dist/index.js` from your site, or `npm link` it into your project.

## Quick start (vanilla JavaScript)

```html
<script type="module">
  import { createVardenWebShield } from '/path/to/@varden/web-shield/dist/index.js';

  const shield = createVardenWebShield({
    endpoint: 'http://127.0.0.1:8000',
    mode: 'enforce', // or 'observe' to never block locally
  });

  await shield.registerTool(document.modelContext, {
    name: 'get_weather',
    description: 'Get the current weather for a city.',
    inputSchema: { type: 'object', properties: { city: { type: 'string' } } },
    annotations: { readOnlyHint: true },
  });
</script>
```

## TypeScript

```ts
import { createVardenWebShield, type RegistrationResult } from '@varden/web-shield';

const shield = createVardenWebShield({ endpoint: 'http://127.0.0.1:8000' });

const result: RegistrationResult = await shield.registerTool(document.modelContext, {
  name: 'send_payment',
  description: 'Submits a real payment. This changes account balances and cannot be undone.',
  annotations: { readOnlyHint: false, destructiveHint: true },
});

if (result.blocked) {
  console.warn('Varden Web Shield blocked this registration:', result.risk.band, result.findings);
} else if (result.approval) {
  console.info('Registered, but invocation will require approval:', result.approval);
}
```

## Opt-in install() wrapper

If you don't want to call `registerTool()` explicitly for every tool, call `install()` once early
on the page. It transparently wraps `document.modelContext.registerTool` (and
`navigator.modelContext.registerTool` if present) so existing `registerTool()` call sites keep
working unmodified.

**Note:** `install()` always calls through to the page's real `registerTool` — it cannot withhold
a registration, because the wrapped function must return synchronously while the report to Varden
happens asynchronously in the background. It gives you detection, risk scoring and dashboard
visibility for zero code changes at every call site, but not `enforce`-mode blocking. If you need a
`block` decision to actually prevent a registration from reaching the agent, call
`shield.registerTool(modelContext, tool)` explicitly instead (see below) — that call awaits the
server's decision before deciding whether to call through.

```js
const shield = createVardenWebShield({ endpoint: 'http://127.0.0.1:8000', mode: 'observe' });
const uninstall = shield.install();

// Elsewhere in the page, completely unmodified:
document.modelContext.registerTool({ name: 'get_weather', description: '...' });
```

## A website registering a tool and reacting to sanitisation

```js
const shield = createVardenWebShield({ endpoint: 'http://127.0.0.1:8000' });

const result = await shield.registerTool(document.modelContext, toolDefinition);
if (result.sanitizedTool) {
  console.info('Varden removed unsafe fragments from this tool before exposing it to the agent.');
}
```

## An agent integration consuming tool output

```js
const shield = createVardenWebShield({ endpoint: 'http://127.0.0.1:8000' });

async function callTool(identityKey, toolFn, args) {
  const invocation = await shield.evaluateInvocation(identityKey, args);
  if (invocation.blocked) throw new Error('Blocked by Varden Web Shield policy');
  if (invocation.approval && invocation.approval.status === 'pending') {
    throw new Error('Awaiting operator approval — see the Web Shield dashboard');
  }

  const start = Date.now();
  let output;
  try {
    output = await toolFn(args);
  } catch (err) {
    await shield.completeInvocation(identityKey, 'error', Date.now() - start, String(err));
    throw err;
  }
  await shield.completeInvocation(identityKey, 'success', Date.now() - start);

  const scan = await shield.scanOutput(identityKey, String(output));
  if (scan.blocked) throw new Error('Tool output blocked by Varden Web Shield');
  return scan.sanitizedOutputText ?? output;
}
```

## Browser extension usage

The extension (`extension/`) does not use this npm package directly — a Manifest V3 service worker
cannot easily `import` an npm-distributed ESM package without its own bundling step, and the
extension's page-world/isolated-world split needs raw script injection rather than a fetch-based
client. Its `src/background.js` reimplements the same three calls
(`/webshield/registrations`, `/webshield/lifecycle`, `/webshield/outputs`) directly. If you are
building your own extension or Node-based agent host instead, this SDK is the more convenient
choice — `shield.health()` and the `connection-change` event give you the same connected/local-only
signal the bundled extension shows in its toolbar badge.

```js
import { createVardenWebShield } from '@varden/web-shield';

const shield = createVardenWebShield({ endpoint: await getConfiguredEndpoint() });
shield.on('connection-change', ({ connected }) => updateBadge(connected));
```

## API surface

- `createVardenWebShield(config)` — construct a client. `config.endpoint` is required.
- `shield.registerTool(modelContext, tool, options?)` — report + (in `enforce` mode) gate a
  registration. Returns `{ identityKey, risk, findings, blocked, approval?, sanitizedTool? }`.
- `shield.unregisterTool(identityKey)`
- `shield.evaluateInvocation(identityKey, args?)` — returns `{ riskScore, riskBand, blocked, approval? }`.
- `shield.completeInvocation(identityKey, status, latencyMs?, error?)`
- `shield.scanOutput(identityKey, outputText, opts?)` — returns `{ outcome, risk, findings, sanitizedOutputText?, blocked }`.
- `shield.health()` — `{ connected, endpoint, latencyMs? }`.
- `shield.install()` — opt-in wrapper; returns an `uninstall()` function.
- `shield.on(event, listener)` — `'registration' | 'invocation' | 'output' | 'connection-change'`.

## Testing

```bash
npm run build
npm test
```

Tests use Node's built-in test runner (`node:test`) with a stubbed `fetch` — no real Varden server
or browser is required.
