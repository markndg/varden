package com.varden;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class VardenClient {
    private final String baseUrl;
    private final String apiKey;
    private final HttpClient client;

    public VardenClient(String baseUrl, String apiKey) {
        this.baseUrl = baseUrl;
        this.apiKey = apiKey;
        this.client = HttpClient.newHttpClient();
    }

    public String guardTool(String toolName, String payloadJson) throws IOException, InterruptedException {
        String body = "{\"action\":{\"type\":\"tool_call\",\"tool\":\"" + toolName + "\",\"args\":" + payloadJson + "},\"payload\":" + payloadJson + "}";
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/sdk/guard"))
                .header("Content-Type", "application/json")
                .header("x-api-key", apiKey)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 403) {
            throw new IOException("Varden blocked action: " + response.body());
        }
        return response.body();
    }

    public String logResult(String payloadJson) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/sdk/log"))
                .header("Content-Type", "application/json")
                .header("x-api-key", apiKey)
                .POST(HttpRequest.BodyPublishers.ofString(payloadJson))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }
}
