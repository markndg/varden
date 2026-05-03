# Varden Java SDK

Varden for Java keeps the application integration as small as possible:

```java
import ai.varden.Varden;
Varden.protect();
```

After that, use the built-in wrappers for the action surfaces Java applications commonly use:

- `Varden.httpClient()` for `java.net.http.HttpClient`
- `Varden.command(...)` for `ProcessBuilder`
- `Varden.guard(...)` for arbitrary tool calls

Environment variables:
- `VARDEN_BASE_URL` default `http://127.0.0.1:8000`
- `VARDEN_API_KEY` optional; auto-bootstrap is attempted when omitted
- `VARDEN_APP_NAME` default `java-app`
- `VARDEN_MODE` default `enforce`
- `VARDEN_FAIL_MODE` default `open`
