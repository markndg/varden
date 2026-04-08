package com.sentinel.sdk;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class SentinelClient {
    private final String baseUrl;
    private final String apiKey;
    private final HttpClient client;

    public SentinelClient(String baseUrl, String apiKey) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length()-1) : baseUrl;
        this.apiKey = apiKey;
        this.client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    }

    public String guardTool(String toolName, String payloadJson) throws IOException, InterruptedException, SentinelException {
        String body = "{\"action\":{\"type\":\"tool_call\",\"tool\":\"" + escape(toolName) + "\"},\"payload\":" + payloadJson + "}";
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + "/sdk/guard"))
                .header("x-api-key", apiKey)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 403) {
            throw new SentinelException("Blocked by Sentinel: " + response.body());
        }
        if (response.statusCode() >= 400) {
            throw new IOException("Sentinel returned " + response.statusCode() + ": " + response.body());
        }
        return response.body();
    }

    public String logResult(String actionJson, String decisionJson, String inputJson, String outputJson) throws IOException, InterruptedException {
        String body = "{\"action\":" + actionJson + ",\"decision\":" + decisionJson + ",\"input_payload\":" + inputJson + ",\"output_payload\":" + outputJson + "}";
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + "/sdk/log"))
                .header("x-api-key", apiKey)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            throw new IOException("Sentinel returned " + response.statusCode() + ": " + response.body());
        }
        return response.body();
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
