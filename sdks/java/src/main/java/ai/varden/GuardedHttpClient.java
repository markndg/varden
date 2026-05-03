package ai.varden;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.Map;

public final class GuardedHttpClient {
    private final HttpClient delegate;
    private final VardenClient client;
    private final VardenConfig config;

    GuardedHttpClient(HttpClient delegate, VardenClient client, VardenConfig config) {
        this.delegate = delegate;
        this.client = client;
        this.config = config;
    }

    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> bodyHandler) throws IOException, InterruptedException {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("headers", request.headers().map());
        payload.put("uri", request.uri().toString());
        payload.put("method", request.method());
        guard(request.uri(), request.method(), payload);
        return delegate.send(request, bodyHandler);
    }

    public <T> java.util.concurrent.CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> bodyHandler) {
        try {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("headers", request.headers().map());
            payload.put("uri", request.uri().toString());
            payload.put("method", request.method());
            guard(request.uri(), request.method(), payload);
        } catch (Exception e) {
            java.util.concurrent.CompletableFuture<HttpResponse<T>> failed = new java.util.concurrent.CompletableFuture<>();
            failed.completeExceptionally(e);
            return failed;
        }
        return delegate.sendAsync(request, bodyHandler);
    }

    private void guard(URI uri, String method, Map<String, Object> payload) throws IOException, InterruptedException {
        Map<String, Object> action = new LinkedHashMap<>();
        action.put("type", "http_request");
        action.put("tool", "java.net.http.HttpClient");
        action.put("url", uri.toString());
        action.put("method", method);
        action.put("args", payload);
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("app_name", config.appName);
        metadata.put("tenant", "default");
        metadata.put("execution_surface", "java-http");
        action.put("metadata", metadata);
        action.put("tenant_id", "default");
        client.guard(action, payload);
    }
}
