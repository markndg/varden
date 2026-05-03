# Varden Rust SDK

Varden for Rust keeps startup to a single line:

```rust
varden::protect()?;
```

After that, use the built-in wrappers for the common action surfaces:

- `varden::http::Client` for outbound HTTP (`reqwest` blocking client)
- `varden::process::Command` for subprocesses
- `varden::guard(...)` for arbitrary tool calls

Environment variables:
- `VARDEN_BASE_URL` default `http://127.0.0.1:8000`
- `VARDEN_API_KEY` optional; auto-bootstrap is attempted when omitted
- `VARDEN_APP_NAME` default `rust-app`
- `VARDEN_MODE` default `enforce`
- `VARDEN_FAIL_MODE` default `open`
