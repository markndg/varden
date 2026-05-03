package ai.varden;

import java.net.http.HttpClient;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Callable;

public final class Varden {
    private static volatile Varden INSTANCE;

    private final VardenConfig config;
    private final VardenClient client;

    private Varden(VardenConfig config) {
        this.config = config;
        this.client = new VardenClient(config);
        this.client.ensureCredentials();
    }

    public static Varden protect() {
        return protect(VardenConfig.fromEnv());
    }

    public static Varden protect(VardenConfig config) {
        INSTANCE = new Varden(config);
        return INSTANCE;
    }

    public static Varden current() {
        if (INSTANCE == null) {
            return protect();
        }
        return INSTANCE;
    }

    public static GuardedHttpClient httpClient() {
        Varden s = current();
        return new GuardedHttpClient(HttpClient.newHttpClient(), s.client, s.config);
    }

    public static GuardedProcessBuilder command(String... command) {
        Varden s = current();
        return GuardedProcessBuilder.of(s.client, s.config, command);
    }

    public static <T> T guard(String toolName, Callable<T> action, Map<String, Object> payload) throws Exception {
        Varden s = current();
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
