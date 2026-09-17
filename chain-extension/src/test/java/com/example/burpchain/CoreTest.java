package com.example.burpchain;

import org.junit.jupiter.api.Test;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.nio.charset.StandardCharsets;
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
    @Test void suggestedStartDoesNotBeginWithUnneededWhitespace() throws Exception {
        String response = "HTTP/1.1 200 OK\r\n\r\n    token=abc123; expires=tomorrow";
        String[] boundaries = DelimiterSuggestions.bestDelimiters(response, "abc123", response.indexOf("abc123"));
        assertFalse(Character.isWhitespace(boundaries[0].charAt(0)));
        String selector = "delim:" + java.util.Base64.getUrlEncoder().encodeToString(boundaries[0].getBytes())
                + "." + java.util.Base64.getUrlEncoder().encodeToString(boundaries[1].getBytes());
        assertEquals("abc123", ChainEngine.extract(response, selector));
    }
    @Test void suggestedStartUsesSelectedOccurrence() throws Exception {
        String response = "first-token=abc; expires=tomorrow\r\nsecond-token=abc; expires=tomorrow";
        String[] boundaries = DelimiterSuggestions.bestDelimiters(response, "abc", response.lastIndexOf("abc"));
        assertTrue(response.indexOf(boundaries[0]) >= response.indexOf("second-token="));
        String selector = "delim:" + java.util.Base64.getUrlEncoder().encodeToString(boundaries[0].getBytes())
                + "." + java.util.Base64.getUrlEncoder().encodeToString(boundaries[1].getBytes());
        assertEquals("abc", ChainEngine.extract(response, selector));
    }
    @Test void insertingVariablePreservesNonUtf8AndUtf8BytesOutsideSelection() {
        for (byte[] accent : List.of(new byte[]{(byte) 0xe9}, "é".getBytes(StandardCharsets.UTF_8))) {
            byte[] prefix = "POST / HTTP/1.1\r\n\r\nname=".getBytes(StandardCharsets.US_ASCII);
            byte[] suffix = "&id=OLD&note=".getBytes(StandardCharsets.US_ASCII);
            byte[] original = new byte[prefix.length + accent.length + suffix.length + accent.length];
            System.arraycopy(prefix, 0, original, 0, prefix.length);
            System.arraycopy(accent, 0, original, prefix.length, accent.length);
            System.arraycopy(suffix, 0, original, prefix.length + accent.length, suffix.length);
            System.arraycopy(accent, 0, original, prefix.length + accent.length + suffix.length, accent.length);
            int start = prefix.length + accent.length + "&id=".length();
            byte[] result = ByteSplice.replace(original, start, start + 3, "{{id}}".getBytes(StandardCharsets.US_ASCII));
            assertArrayEquals(accent, java.util.Arrays.copyOfRange(result, prefix.length, prefix.length + accent.length));
            assertArrayEquals(accent, java.util.Arrays.copyOfRange(result, result.length - accent.length, result.length));
        }
    }
    @Test void renderingVariablesPreservesOriginalRequestBytesAndSetsByteLength() {
        for (byte[] accent : List.of(new byte[]{(byte) 0xe9}, "é".getBytes(StandardCharsets.UTF_8))) {
            byte[] head = "POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\nname=".getBytes(StandardCharsets.US_ASCII);
            byte[] tail = "&id={{id}}".getBytes(StandardCharsets.US_ASCII);
            byte[] template = new byte[head.length + accent.length + tail.length];
            System.arraycopy(head, 0, template, 0, head.length);
            System.arraycopy(accent, 0, template, head.length, accent.length);
            System.arraycopy(tail, 0, template, head.length + accent.length, tail.length);
            byte[] rendered = ByteTemplate.render(template, Map.of("id", "42"),
                    value -> value.getBytes(StandardCharsets.US_ASCII));
            String text = new String(rendered, StandardCharsets.ISO_8859_1);
            assertTrue(text.contains("Content-Length: " + ("name=&id=42".length() + accent.length)));
            int body = text.indexOf("\r\n\r\n") + 4;
            assertArrayEquals(accent, java.util.Arrays.copyOfRange(rendered, body + "name=".length(),
                    body + "name=".length() + accent.length));
            assertTrue(text.endsWith("&id=42"));
        }
    }
}
