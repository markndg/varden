package ai.varden;

public final class VardenConfig {
    public final String baseUrl;
    public final String apiKey;
    public final String appName;
    public final String tenant;
    public final String mode;
    public final String failMode;
    public final int timeoutMillis;

    public VardenConfig(String baseUrl, String apiKey, String appName, String tenant, String mode, String failMode, int timeoutMillis) {
        this.baseUrl = baseUrl;
        this.apiKey = apiKey;
        this.appName = appName;
        this.tenant = tenant;
        this.mode = mode;
        this.failMode = failMode;
        this.timeoutMillis = timeoutMillis;
    }

    public static VardenConfig fromEnv() {
        return new VardenConfig(
            env("VARDEN_BASE_URL", "http://127.0.0.1:8000"),
            env("VARDEN_API_KEY", null),
            env("VARDEN_APP_NAME", "java-app"),
            "default",
            env("VARDEN_MODE", "enforce"),
            env("VARDEN_FAIL_MODE", "open"),
            Integer.parseInt(env("VARDEN_TIMEOUT_MILLIS", "5000"))
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
