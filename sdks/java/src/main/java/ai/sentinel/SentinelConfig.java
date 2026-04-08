package ai.sentinel;

public final class SentinelConfig {
    public final String baseUrl;
    public final String apiKey;
    public final String appName;
    public final String tenant;
    public final String mode;
    public final String failMode;
    public final int timeoutMillis;

    public SentinelConfig(String baseUrl, String apiKey, String appName, String tenant, String mode, String failMode, int timeoutMillis) {
        this.baseUrl = baseUrl;
        this.apiKey = apiKey;
        this.appName = appName;
        this.tenant = tenant;
        this.mode = mode;
        this.failMode = failMode;
        this.timeoutMillis = timeoutMillis;
    }

    public static SentinelConfig fromEnv() {
        return new SentinelConfig(
            env("SENTINEL_BASE_URL", "http://127.0.0.1:8000"),
            env("SENTINEL_API_KEY", null),
            env("SENTINEL_APP_NAME", "java-app"),
            "default",
            env("SENTINEL_MODE", "enforce"),
            env("SENTINEL_FAIL_MODE", "open"),
            Integer.parseInt(env("SENTINEL_TIMEOUT_MILLIS", "5000"))
        );
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            value = System.getProperty(name.toLowerCase().replace('_', '.'));
        }
        return (value == null || value.isBlank()) ? fallback : value;
    }
}
