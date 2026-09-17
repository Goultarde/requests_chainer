package com.example.burpchain;

import org.junit.jupiter.api.Test;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import static org.junit.jupiter.api.Assertions.*;

class CoreTest {
    @Test void nestedArrayAndEscapedKey() throws Exception {
        String json = "{\"outer\":{\"a/b\":[{\"id\":\"123\"},{\"id\":\"456\"}]}}";
        assertEquals("/outer/a~1b/1/id", JsonPaths.pathsForValue(json, "456").getFirst());
        assertEquals("456", JsonPaths.extract(json, "/outer/a~1b/1/id"));
    }
    @Test void duplicateValuesRequireChoice() throws Exception {
        assertEquals(2, JsonPaths.pathsForValue("{\"a\":{\"id\":7},\"b\":{\"id\":7}}", "7").size());
    }
    @Test void renderAndMissingValue() {
        assertEquals("POST /items/7 HTTP/1.1", Template.render("POST /items/{{id}} HTTP/1.1", Map.of("id", "7")));
        assertThrows(IllegalArgumentException.class, () -> Template.render("{{id}}", Map.of()));
    }
    @Test void contentLengthTracksUtf8Substitution() {
        String request = "POST /use HTTP/1.1\r\nContent-Length: 20\r\n\r\n{\"id\":\"{{id}}\"}";
        String rendered = Template.renderHttpRequest(request, Map.of("id", "é-42"));
        assertTrue(rendered.contains("Content-Length: 14\r\n"));
    }
    @Test void runsThreeRequestsInOrderAndUsesFirstVariableInThird() throws Exception {
        List<String> sent = new ArrayList<>();
        List<String> events = new ArrayList<>();
        List<ChainEngine.Step> steps = List.of(new ChainEngine.Step("POST /start", Map.of("id", "/result/session/id")), new ChainEngine.Step("POST /prepare", Map.of()), new ChainEngine.Step("POST /use/{{id}}", Map.of()));
        Map<String, String> result = ChainEngine.run(steps, (index, raw) -> { sent.add(raw); return index == 0 ? new ChainEngine.Response(200, "{\"result\":{\"session\":{\"id\":\"abc-42\"}}}") : new ChainEngine.Response(200, "{}"); }, events::add);
        assertEquals(List.of("POST /start", "POST /prepare", "POST /use/abc-42"), sent);
        assertEquals("abc-42", result.get("id"));
        assertTrue(events.contains("Step 1: id = abc-42"));
    }
    @Test void stopsBeforeUsingMissingVariable() {
        List<ChainEngine.Step> steps = List.of(new ChainEngine.Step("POST /use/{{id}}", Map.of()));
        assertThrows(Exception.class, () -> ChainEngine.run(steps, (index, raw) -> new ChainEngine.Response(200, "{}"), message -> {}));
    }
    @Test void extractsWithRegexCaptureGroup() throws Exception {
        String regex = "regex:\"id\"\\s*:\\s*\"([^\"]+)\"";
        var steps = List.of(new ChainEngine.Step("GET /", Map.of("id", regex)));
        var result = ChainEngine.run(steps, (index, raw) -> new ChainEngine.Response(200, "{\"data\":{\"object\":{\"id\":\"abc123\"}}}"), message -> {});
        assertEquals("abc123", result.get("id"));
        assertEquals("abc123", ChainEngine.extract("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"data\":{\"object\":{\"id\":\"abc123\"}}}", "/data/object/id"));
    }
    @Test void extractsWithStartAndEndDelimiters() throws Exception {
        String prefix = "\"id\":\"";
        String suffix = "\"";
        String selector = "delim:" + java.util.Base64.getUrlEncoder().encodeToString(prefix.getBytes()) + "." + java.util.Base64.getUrlEncoder().encodeToString(suffix.getBytes());
        assertEquals("abc123", ChainEngine.extract("{\"id\":\"abc123\"}", selector));
    }
    @Test void extractsCookieWithMacroStyleRegexAndCaseOption() throws Exception {
        String body = "Set-Cookie: __Secure-ENID=CpcABC_123; expires=Sat, 16-Oct-2027 09:26:57 GMT";
        assertEquals("CpcABC_123", ChainEngine.extract(body, "regex:\\-ENID=(.*?); expires="));
        assertEquals("CpcABC_123", ChainEngine.extract(body, "regexi:\\-enid=(.*?); EXPIRES="));
    }
}
