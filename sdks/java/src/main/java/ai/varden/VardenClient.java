package ai.varden;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

public final class VardenClient {
    private final VardenConfig config;
    private final HttpClient http;
    private volatile String apiKey;

    public VardenClient(VardenConfig config) {
        this.config = config;
        this.apiKey = config.apiKey;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(config.timeoutMillis)).build();
    }

    public void ensureCredentials() {
        if (apiKey != null && !apiKey.isBlank()) return;
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(config.baseUrl + "/sdk/bootstrap")).GET().timeout(Duration.ofMillis(config.timeoutMillis)).build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() / 100 == 2) {
                Object parsed = Json.parse(resp.body());
                if (parsed instanceof Map) {
                    Object key = ((Map<?, ?>) parsed).get("bootstrap_api_key");
                    if (key != null) apiKey = String.valueOf(key);
                }
            }
        } catch (Exception ignored) {
        }
    }

    public VardenGuardResult guard(Map<String, Object> action, Object payload) throws IOException, InterruptedException {
        ensureCredentials();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("action", action);
        body.put("payload", payload);
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(config.baseUrl + "/sdk/guard"))
            .POST(HttpRequest.BodyPublishers.ofString(Json.stringify(body)))
            .header("Content-Type", "application/json")
            .timeout(Duration.ofMillis(config.timeoutMillis));
        if (apiKey != null && !apiKey.isBlank()) builder.header("x-api-key", apiKey);
        HttpResponse<String> resp = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        Object parsed = Json.parse(resp.body());
        @SuppressWarnings("unchecked") Map<String, Object> data = parsed instanceof Map ? (Map<String, Object>) parsed : new LinkedHashMap<>();
        @SuppressWarnings("unchecked") Map<String, Object> decisionRaw = data.get("decision") instanceof Map ? (Map<String, Object>) data.get("decision") : new LinkedHashMap<>();
        @SuppressWarnings("unchecked") Map<String, Object> actionRaw = data.get("action") instanceof Map ? (Map<String, Object>) data.get("action") : new LinkedHashMap<>();
        VardenGuardResult result = new VardenGuardResult(
            new VardenDecision(String.valueOf(decisionRaw.getOrDefault("action", "allow")), String.valueOf(decisionRaw.getOrDefault("reason", "")), decisionRaw),
            actionRaw,
            data.get("event_id") instanceof Number ? ((Number) data.get("event_id")).intValue() : null
        );
        if (resp.statusCode() == 403) {
            throw new VardenBlockedException(String.valueOf(data.getOrDefault("detail", "blocked by Varden")), result);
        }
        if (resp.statusCode() / 100 != 2) {
            throw new IOException("Varden guard failed with status " + resp.statusCode() + ": " + resp.body());
        }
        return result;
    }
}
