package com.example.burpchain;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ByteArray;
import java.util.LinkedHashMap;
import java.util.Map;

final class ChainStep {
    final HttpService service;
    final String url;
    String requestTemplate;
    byte[] requestBytes;
    java.time.Instant capturedAt;
    byte[] capturedRequestBytes;
    boolean enabled = true;
    String lastResponse = "";
    byte[] lastResponseBytes = new byte[0];
    String lastResponseBody = "";
    final Map<String, String> outputs = new LinkedHashMap<>();

    ChainStep(HttpRequestResponse item) {
        service = item.httpService();
        url = item.request().url();
        setRequest(item.request());
        capturedRequestBytes = requestBytes.clone();
        capturedAt = item.timingData().map(t -> t.timeRequestSent()).map(t -> t.toInstant()).orElse(null);
        if (item.hasResponse()) {
            lastResponse = item.response().toString();
            lastResponseBytes = item.response().toByteArray().getBytes();
            lastResponseBody = item.response().bodyToString();
        }
    }

    ChainStep(HttpService service, String requestTemplate) {
        this.service = service;
        this.url = HttpRequest.httpRequest(service, requestTemplate).url();
        setRequest(HttpRequest.httpRequest(service, requestTemplate));
    }

    void setRequest(HttpRequest request) {
        requestTemplate = request.toString();
        requestBytes = request.toByteArray().getBytes();
    }

    void setTemplateText(String template) {
        setRequest(HttpRequest.httpRequest(service, template));
    }

    HttpRequest request() {
        return HttpRequest.httpRequest(service, ByteArray.byteArray(requestBytes));
    }
}
