package com.example.burpchain;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Passive backward dependency analysis of a chronological, same-origin capture. */
final class AutoChainFinder {
    record Capture(int id, String origin, String label, byte[] request, byte[] response, long sentAt, long completedAt) {
        Capture(int id, String origin, String label, byte[] request, byte[] response) {
            this(id, origin, label, request, response, id * 10L, id * 10L + 1);
        }
    }
    record SelectionSource(Capture capture, String selector, String description) {
        @Override public String toString() {
            String label = capture.label();
            return "History #" + capture.id() + " · " + (label.length() > 120 ? label.substring(0, 117) + "..." : label)
                    + " · " + description;
        }
    }
    record Link(int sourceId, int consumerId, String variable, String description) {}
    record PlannedStep(Capture capture, byte[] template, Map<String, String> outputs) {}
    record Plan(List<PlannedStep> steps, List<Link> links, List<String> warnings) {}
    private record Candidate(byte[] value, String selector, String description) {}
    private record Replacement(int start, int end, String variable) {}
    private final List<Capture> history;
    private int minimumValueLength = 6;
    private final Map<Integer, List<Candidate>> candidates = new LinkedHashMap<>(32, 0.75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<Integer, List<Candidate>> entry) { return size() > 32; }
    };
    private final Map<Integer, List<Replacement>> replacements = new HashMap<>();
    private final Map<Integer, Map<String, String>> outputs = new HashMap<>();
    private final Map<String, String> names = new LinkedHashMap<>();
    private final Set<Integer> included = new TreeSet<>();
    private final List<Link> links = new ArrayList<>();
    private final Set<String> warnings = new LinkedHashSet<>();

    AutoChainFinder(List<Capture> history) { this.history = List.copyOf(history); }

    /** Only the explicitly selected bytes are searched. No recursive discovery or other replacements. */
    List<SelectionSource> findSelectionSources(int targetIndex, int start, int end) throws IOException {
        if (targetIndex < 0 || targetIndex >= history.size()) throw new IOException("Target not found in captured history");
        Capture target = history.get(targetIndex);
        if (start < 0 || end <= start || end > target.request().length)
            throw new IOException("Select a non-empty byte range in the request");
        byte[] selected = Arrays.copyOfRange(target.request(), start, end);
        if (selected.length > 262144) throw new IOException("Selected value exceeds 256 KiB");
        minimumValueLength = 1;
        List<SelectionSource> result = new ArrayList<>();
        for (int i = targetIndex - 1; i >= 0; i--) {
            if (Thread.currentThread().isInterrupted()) throw new IOException("Analysis cancelled");
            Capture source = history.get(i);
            if (!source.origin().equals(target.origin()) || source.response().length == 0
                    || source.completedAt() > target.sentAt()) continue;
            for (Candidate candidate : values(source)) {
                if (Arrays.equals(selected, candidate.value()))
                    result.add(new SelectionSource(source, candidate.selector(), candidate.description()));
            }
        }
        return List.copyOf(result);
    }

    List<String> discoveryWarnings() { return List.copyOf(warnings); }

    Plan find(int targetIndex) throws IOException {
        if (targetIndex < 0 || targetIndex >= history.size()) throw new IOException("Target not found in captured history");
        visit(targetIndex);
        List<PlannedStep> planned = new ArrayList<>();
        for (int index : included) {
            byte[] raw = history.get(index).request();
            List<Replacement> edits = replacements.getOrDefault(index, List.of()).stream()
                    .sorted(Comparator.comparingInt(Replacement::start).reversed()).toList();
            for (Replacement edit : edits) raw = ByteSplice.replace(raw, edit.start(), edit.end(),
                    ("{{" + edit.variable() + "|bytes}}").getBytes(StandardCharsets.US_ASCII));
            planned.add(new PlannedStep(history.get(index), raw, Map.copyOf(outputs.getOrDefault(index, Map.of()))));
        }
        return new Plan(List.copyOf(planned), List.copyOf(links), List.copyOf(warnings));
    }

    private void visit(int consumerIndex) throws IOException {
        if (!included.add(consumerIndex)) return;
        if (included.size() > 100) throw new IOException("More than 100 dependent steps; narrow the history before retrying");
        if (Thread.currentThread().isInterrupted()) throw new IOException("Analysis cancelled");
        Capture consumer = history.get(consumerIndex);
        String requestView = new String(consumer.request(), StandardCharsets.ISO_8859_1);
        if (consumer.request().length > AutoValue.MAX_BYTES) throw new IOException("Request exceeds automatic analysis limit (2 MiB)");
        List<Replacement> edits = new ArrayList<>();
        replacements.put(consumerIndex, edits);
        Set<Integer> producers = new TreeSet<>();
        for (int sourceIndex = consumerIndex - 1; sourceIndex >= 0; sourceIndex--) {
            Capture source = history.get(sourceIndex);
            if (!source.origin().equals(consumer.origin()) || source.response().length == 0
                    || source.completedAt() > consumer.sentAt()) continue;
            if (Thread.currentThread().isInterrupted()) throw new IOException("Analysis cancelled");
            List<Candidate> values = candidates.get(sourceIndex);
            if (values == null) {
                values = values(source);
                candidates.put(sourceIndex, values);
            }
            for (Candidate candidate : values) {
                List<Integer> offsets = matches(consumer.request(), candidate.value());
                for (int offset : offsets) {
                    int end = offset + candidate.value().length;
                    if (!allowed(requestView, offset, end)) continue;
                    if (edits.stream().anyMatch(e -> offset < e.end() && end > e.start())) continue;
                    String key = sourceIndex + ":" + candidate.selector();
                    String name = names.computeIfAbsent(key, k -> "auto_" + (names.size() + 1));
                    outputs.computeIfAbsent(sourceIndex, k -> new LinkedHashMap<>()).put(name, candidate.selector());
                    edits.add(new Replacement(offset, end, name));
                    producers.add(sourceIndex);
                    Link link = new Link(source.id(), consumer.id(), name, candidate.description());
                    if (!links.contains(link)) links.add(link);
                }
            }
        }
        for (int producer : producers) visit(producer);
    }

    private List<Candidate> values(Capture source) {
        List<Candidate> result = new ArrayList<>();
        try {
            AutoValue.Message message = AutoValue.message(source.response());
            for (var header : message.headers().entrySet()) {
                String key = header.getKey();
                if (key.equals("set-cookie")) {
                    for (String cookie : header.getValue()) {
                        String pair = cookie.split(";", 2)[0];
                        int equal = pair.indexOf('=');
                        if (equal > 0) add(result, pair.substring(equal + 1).getBytes(StandardCharsets.ISO_8859_1), "cookie", pair.substring(0, equal).trim(), "wire", "Cookie " + pair.substring(0, equal).trim(), false);
                    }
                } else if (header.getValue().size() == 1 && (key.startsWith("x-") || key.equals("location") || key.equals("authorization"))) {
                    add(result, header.getValue().getFirst().getBytes(StandardCharsets.ISO_8859_1), "header", key, "wire", "Header " + key, false);
                }
            }
            List<String> modes = new ArrayList<>(List.of("wire"));
            if (message.headers().containsKey("content-encoding")) modes.add("http");
            else if (message.body().length > 2 && message.body()[0] == 31 && message.body()[1] == (byte)139) modes.add("gzip");
            else if (message.body().length > 2 && message.body()[0] == 0x78) modes.add("deflate");
            for (String mode : modes) {
                byte[] body;
                try { body = AutoValue.decoded(message, mode); }
                catch (IOException ex) { warnings.add("History #" + source.id() + ": " + ex.getMessage()); continue; }
                JsonNode json = null;
                try { json = AutoValue.JSON.readTree(body); } catch (IOException ignored) { }
                if (json != null && json.isContainerNode()) walk(result, json, "", mode);
                else if (body.length >= 8 && body.length <= 262144) add(result, body, "body", "", mode, "Complete body (" + mode + ")", true);
            }
        } catch (IOException | RuntimeException ex) {
            warnings.add("History #" + source.id() + " skipped: " + ex.getMessage());
        }
        // Prefer the longest exact value, then the simplest encoding of that value.
        result.sort(Comparator.comparingInt((Candidate value) -> value.value().length).reversed());
        return result;
    }
    private void walk(List<Candidate> out, JsonNode node, String path, String mode) throws IOException {
        if (out.size() >= 512) { warnings.add("Some response fields were skipped (512 candidate limit)"); return; }
        if (node.isObject()) {
            var fields = node.fields();
            while (fields.hasNext()) {
                var field = fields.next();
                walk(out, field.getValue(), path + "/" + field.getKey().replace("~", "~0").replace("/", "~1"), mode);
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) walk(out, node.get(i), path + "/" + i, mode);
        } else if (node.isTextual() || node.isIntegralNumber()) {
            add(out, node.asText().getBytes(StandardCharsets.UTF_8), "json", path, mode, "JSON " + path + " (" + mode + ")", false);
        }
    }
    private void add(List<Candidate> out, byte[] value, String kind, String path, String mode, String description, boolean binary) throws IOException {
        if (value.length < minimumValueLength || value.length > 262144) return;
        // Short numbers and ordinary booleans/constants are not persuasive dependencies.
        String text = new String(value, StandardCharsets.UTF_8);
        if (!binary && (text.isBlank() || Set.of("application/json", "text/html", "success", "unknown", "default", "enabled", "disabled").contains(text.toLowerCase(Locale.ROOT)))) return;
        Set<String> variants = new HashSet<>();
        for (String transform : binary ? List.of("raw", "base64", "base64url", "hex") : List.of("raw", "json", "url", "form", "base64", "base64url")) {
            if (out.size() >= 512) { warnings.add("Some response fields were skipped (512 candidate limit)"); return; }
            byte[] encoded = AutoValue.transform(value, transform);
            if (!variants.add(Base64.getEncoder().encodeToString(encoded))) continue;
            AutoValue.Recipe recipe = new AutoValue.Recipe(kind, path, mode, transform);
            out.add(new Candidate(encoded, AutoValue.selector(recipe), description + " → " + transform));
        }
    }
    private static List<Integer> matches(byte[] haystack, byte[] needle) throws IOException {
        List<Integer> result = new ArrayList<>();
        int[] prefix = new int[needle.length];
        for (int i = 1, j = 0; i < needle.length; i++) {
            while (j > 0 && needle[i] != needle[j]) j = prefix[j - 1];
            if (needle[i] == needle[j]) j++;
            prefix[i] = j;
        }
        for (int i = 0, j = 0; i < haystack.length; i++) {
            while (j > 0 && haystack[i] != needle[j]) j = prefix[j - 1];
            if (haystack[i] == needle[j]) j++;
            if (j == needle.length) {
                int start = i - j + 1;
                if (!(start > 0 && word(needle[0]) && word(haystack[start - 1]))
                        && !(i + 1 < haystack.length && word(needle[j - 1]) && word(haystack[i + 1]))) result.add(start);
                if (result.size() > 256) throw new IOException("More than 256 occurrences of a candidate value; narrow the target request");
                j = 0;
            }
        }
        return result;
    }
    private static boolean word(byte b) { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-'; }
    private static boolean allowed(String view, int start, int end) {
        int body = view.indexOf("\r\n\r\n"), width = 4;
        if (body < 0) { body = view.indexOf("\n\n"); width = 2; }
        if (body >= 0 && start >= body + width) {
            String headers = view.substring(0, body).toLowerCase(Locale.ROOT);
            if (headers.contains("application/json") || headers.contains("+json")) {
                // A response value matching an object key is not a request-value dependency.
                if (start > 0 && view.charAt(start - 1) == '"' && end < view.length() && view.charAt(end) == '"') {
                    int next = end + 1;
                    while (next < view.length() && Character.isWhitespace(view.charAt(next))) next++;
                    if (next < view.length() && view.charAt(next) == ':') return false;
                }
            }
            return true;
        }
        int lineStart = view.lastIndexOf('\n', Math.max(0, start - 1)) + 1;
        int lineEnd = view.indexOf('\n', start);
        if (lineEnd >= 0 && end > lineEnd) return false;
        if (lineStart == 0) return start > view.indexOf(' ') && end <= view.lastIndexOf(" HTTP/", lineEnd < 0 ? view.length() : lineEnd);
        int colon = view.indexOf(':', lineStart);
        if (colon < 0 || colon >= start) return false;
        String header = view.substring(lineStart, colon).toLowerCase(Locale.ROOT);
        return !header.startsWith("sec-") && !Set.of("host", "content-length", "content-type", "accept", "accept-encoding", "accept-language",
                "user-agent", "connection", "referer", "priority", "upgrade-insecure-requests", "cache-control", "transfer-encoding", "te").contains(header);
    }
}
