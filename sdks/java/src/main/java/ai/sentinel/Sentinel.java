package ai.sentinel;

import java.net.http.HttpClient;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Callable;

public final class Sentinel {
    private static volatile Sentinel INSTANCE;

    private final SentinelConfig config;
    private final SentinelClient client;

    private Sentinel(SentinelConfig config) {
        this.config = config;
        this.client = new SentinelClient(config);
        this.client.ensureCredentials();
    }

    public static Sentinel protect() {
        return protect(SentinelConfig.fromEnv());
    }

    public static Sentinel protect(SentinelConfig config) {
        INSTANCE = new Sentinel(config);
        return INSTANCE;
    }

    public static Sentinel current() {
        if (INSTANCE == null) {
            return protect();
        }
        return INSTANCE;
    }

    public static GuardedHttpClient httpClient() {
        Sentinel s = current();
        return new GuardedHttpClient(HttpClient.newHttpClient(), s.client, s.config);
    }

    public static GuardedProcessBuilder command(String... command) {
        Sentinel s = current();
        return GuardedProcessBuilder.of(s.client, s.config, command);
    }

    public static <T> T guard(String toolName, Callable<T> action, Map<String, Object> payload) throws Exception {
        Sentinel s = current();
        Map<String, Object> actionBody = new LinkedHashMap<>();
        actionBody.put("type", "tool_call");
        actionBody.put("tool", toolName);
        actionBody.put("args", payload);
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("app_name", s.config.appName);
        metadata.put("tenant", "default");
        metadata.put("execution_surface", "java-guard");
        actionBody.put("metadata", metadata);
        actionBody.put("tenant_id", "default");
        s.client.guard(actionBody, payload);
        return action.call();
    }
}
