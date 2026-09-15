package com.example.burpchain;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import java.util.LinkedHashMap;
import java.util.Map;

final class ChainStep {
    final HttpService service;
    final String url;
    String requestTemplate;
    String lastResponse = "";
    String lastResponseBody = "";
    final Map<String, String> outputs = new LinkedHashMap<>();

    ChainStep(HttpRequestResponse item) {
        service = item.httpService();
        url = item.request().url();
        requestTemplate = item.request().toString();
        if (item.hasResponse()) {
            lastResponse = item.response().toString();
            lastResponseBody = item.response().bodyToString();
        }
    }
}
