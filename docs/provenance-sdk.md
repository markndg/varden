# Provenance SDK

```python
import varden

varden.protect()

# Observe untrusted external content entering the agent context:
varden.observe_provenance(
    source_type="web_page",
    origin="https://untrusted.example/page",
    trust_level="untrusted",
)

# Or scope a nested block:
with varden.provenance_scope([{
    "source_type": "mcp_tool_response",
    "origin": "mcp://search",
    "trust_level": "untrusted",
}]):
    ...
```

Client-asserted `trust_level=trusted` is downgraded to `unknown`. Only the control plane issues verified delegations (`POST /authority/delegations`).

`tagged()` lineage continues to flow into `metadata.lineage` and is consumed by authority-flow analysis.
