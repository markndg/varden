package ai.sentinel;

import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class GuardedProcessBuilder {
    private final ProcessBuilder delegate;
    private final SentinelClient client;
    private final SentinelConfig config;

    GuardedProcessBuilder(List<String> command, SentinelClient client, SentinelConfig config) {
        this.delegate = new ProcessBuilder(command);
        this.client = client;
        this.config = config;
    }

    public GuardedProcessBuilder inheritIO() {
        delegate.inheritIO();
        return this;
    }

    public Process start() throws IOException, InterruptedException {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("command", delegate.command());
        Map<String, Object> action = new LinkedHashMap<>();
        action.put("type", "tool_call");
        action.put("tool", "java.lang.ProcessBuilder.start");
        action.put("args", payload);
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("app_name", config.appName);
        metadata.put("tenant", "default");
        metadata.put("execution_surface", "java-process");
        action.put("metadata", metadata);
        action.put("tenant_id", "default");
        client.guard(action, payload);
        return delegate.start();
    }

    public static GuardedProcessBuilder of(SentinelClient client, SentinelConfig config, String... command) {
        return new GuardedProcessBuilder(Arrays.asList(command), client, config);
    }
}
