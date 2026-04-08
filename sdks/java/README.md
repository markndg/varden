# Sentinel Java SDK

Sentinel for Java keeps the application integration as small as possible:

```java
import ai.sentinel.Sentinel;
Sentinel.protect();
```

After that, use the built-in wrappers for the action surfaces Java applications commonly use:

- `Sentinel.httpClient()` for `java.net.http.HttpClient`
- `Sentinel.command(...)` for `ProcessBuilder`
- `Sentinel.guard(...)` for arbitrary tool calls

Environment variables:
- `SENTINEL_BASE_URL` default `http://127.0.0.1:8000`
- `SENTINEL_API_KEY` optional; auto-bootstrap is attempted when omitted
- `SENTINEL_APP_NAME` default `java-app`
- `SENTINEL_MODE` default `enforce`
- `SENTINEL_FAIL_MODE` default `open`
