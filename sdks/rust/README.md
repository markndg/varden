# Sentinel Rust SDK

Sentinel for Rust keeps startup to a single line:

```rust
sentinel::protect()?;
```

After that, use the built-in wrappers for the common action surfaces:

- `sentinel::http::Client` for outbound HTTP (`reqwest` blocking client)
- `sentinel::process::Command` for subprocesses
- `sentinel::guard(...)` for arbitrary tool calls

Environment variables:
- `SENTINEL_BASE_URL` default `http://127.0.0.1:8000`
- `SENTINEL_API_KEY` optional; auto-bootstrap is attempted when omitted
- `SENTINEL_APP_NAME` default `rust-app`
- `SENTINEL_MODE` default `enforce`
- `SENTINEL_FAIL_MODE` default `open`
