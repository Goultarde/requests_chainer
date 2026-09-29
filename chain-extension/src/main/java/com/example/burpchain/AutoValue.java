package com.example.burpchain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;

/** Persistable, byte-preserving extraction recipe used by discovered dependencies. */
final class AutoValue {
    static final ObjectMapper JSON = new ObjectMapper();
    static final int MAX_BYTES = 2 * 1024 * 1024;
    record Recipe(String kind, String path, String decoding, String transform) {}
    record Message(Map<String, List<String>> headers, byte[] body) {}

    static String selector(Recipe recipe) {
        try { return "auto:" + Base64.getUrlEncoder().withoutPadding().encodeToString(JSON.writeValueAsBytes(recipe)); }
        catch (IOException ex) { throw new IllegalArgumentException(ex); }
    }
    static byte[] extract(byte[] response, String selector) throws IOException {
        Recipe recipe = JSON.readValue(Base64.getUrlDecoder().decode(selector.substring(5)), Recipe.class);
        Message message = message(response);
        byte[] body = decoded(message, recipe.decoding());
        byte[] value;
        switch (recipe.kind()) {
            case "body" -> value = body;
            case "json" -> {
                JsonNode node = JSON.readTree(body).at(recipe.path());
                if (node.isMissingNode() || node.isNull() || node.isContainerNode())
                    throw new IOException("Automatic JSON extraction missing: " + recipe.path());
                value = node.asText().getBytes(StandardCharsets.UTF_8);
            }
            case "header" -> {
                List<String> entries = message.headers().getOrDefault(recipe.path().toLowerCase(Locale.ROOT), List.of());
                if (entries.size() != 1) throw new IOException("Automatic header extraction missing or ambiguous: " + recipe.path());
                value = entries.getFirst().getBytes(StandardCharsets.ISO_8859_1);
            }
            case "cookie" -> {
                List<String> matches = new ArrayList<>();
                for (String cookie : message.headers().getOrDefault("set-cookie", List.of())) {
                    String pair = cookie.split(";", 2)[0];
                    int equal = pair.indexOf('=');
                    if (equal > 0 && pair.substring(0, equal).trim().equals(recipe.path())) matches.add(pair.substring(equal + 1));
                }
                if (matches.size() != 1) throw new IOException("Automatic cookie extraction missing or ambiguous: " + recipe.path());
                value = matches.getFirst().getBytes(StandardCharsets.ISO_8859_1);
            }
            default -> throw new IOException("Unknown automatic extractor: " + recipe.kind());
        }
        if (value.length == 0) throw new IOException("Automatic extractor produced an empty value");
        return transform(value, recipe.transform());
    }
    static byte[] transform(byte[] value, String transform) throws IOException {
        return switch (transform) {
            case "raw" -> value;
            case "base64" -> Base64.getEncoder().encode(value);
            case "base64url" -> Base64.getUrlEncoder().withoutPadding().encode(value);
            case "hex" -> HexFormat.of().formatHex(value).getBytes(StandardCharsets.US_ASCII);
            case "json" -> {
                byte[] json = JSON.writeValueAsBytes(new String(value, StandardCharsets.UTF_8));
                yield Arrays.copyOfRange(json, 1, json.length - 1);
            }
            case "url", "form" -> {
                StringBuilder out = new StringBuilder();
                for (byte b : value) {
                    int c = b & 255;
                    if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || "-._~".indexOf(c) >= 0) out.append((char)c);
                    else if (c == ' ' && transform.equals("form")) out.append('+');
                    else out.append('%').append("0123456789ABCDEF".charAt(c >> 4)).append("0123456789ABCDEF".charAt(c & 15));
                }
                yield out.toString().getBytes(StandardCharsets.US_ASCII);
            }
            default -> throw new IOException("Unknown automatic encoding: " + transform);
        };
    }
    static Message message(byte[] raw) throws IOException {
        if (raw.length > MAX_BYTES) throw new IOException("Message exceeds automatic analysis limit (2 MiB)");
        String view = new String(raw, StandardCharsets.ISO_8859_1);
        int boundary = view.indexOf("\r\n\r\n"), width = 4;
        if (boundary < 0) { boundary = view.indexOf("\n\n"); width = 2; }
        if (boundary < 0) throw new IOException("HTTP message has no header/body separator");
        Map<String, List<String>> headers = new LinkedHashMap<>();
        for (String line : view.substring(0, boundary).split("\r?\n")) {
            int colon = line.indexOf(':');
            if (colon > 0) headers.computeIfAbsent(line.substring(0, colon).toLowerCase(Locale.ROOT), k -> new ArrayList<>()).add(line.substring(colon + 1).trim());
        }
        byte[] body = Arrays.copyOfRange(raw, boundary + width, raw.length);
        if (headers.getOrDefault("transfer-encoding", List.of()).stream().anyMatch(v -> v.toLowerCase(Locale.ROOT).contains("chunked"))) body = unchunk(body);
        return new Message(headers, body);
    }
    static byte[] decoded(Message message, String mode) throws IOException {
        byte[] body = message.body();
        if (mode.equals("wire")) return body;
        if (mode.equals("gzip")) return inflate(body, "gzip");
        if (mode.equals("deflate")) return inflate(body, "deflate");
        if (!mode.equals("http")) throw new IOException("Unknown response decoding: " + mode);
        String[] encodings = String.join(",", message.headers().getOrDefault("content-encoding", List.of())).split(",");
        for (int i = encodings.length - 1; i >= 0; i--) {
            String encoding = encodings[i].trim().toLowerCase(Locale.ROOT);
            if (!encoding.isEmpty() && !encoding.equals("identity")) body = inflate(body, encoding);
        }
        return body;
    }
    private static byte[] inflate(byte[] input, String type) throws IOException {
        try (InputStream stream = switch (type) {
            case "gzip" -> new GZIPInputStream(new ByteArrayInputStream(input));
            case "deflate" -> new InflaterInputStream(new ByteArrayInputStream(input));
            default -> throw new IOException("Unsupported Content-Encoding: " + type);
        }) {
            byte[] output = stream.readNBytes(MAX_BYTES + 1);
            if (output.length > MAX_BYTES) throw new IOException("Decoded response exceeds 2 MiB");
            return output;
        }
    }
    private static byte[] unchunk(byte[] body) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int at = 0;
        while (at < body.length) {
            int end = at;
            while (end + 1 < body.length && !(body[end] == 13 && body[end + 1] == 10)) end++;
            if (end + 1 >= body.length) throw new IOException("Incomplete chunk header");
            int size;
            try { size = Integer.parseInt(new String(body, at, end - at, StandardCharsets.US_ASCII).split(";", 2)[0].trim(), 16); }
            catch (NumberFormatException ex) { throw new IOException("Invalid chunk size", ex); }
            at = end + 2;
            if (size == 0) return out.toByteArray();
            if (size < 0 || size > body.length - at - 2 || body[at + size] != 13 || body[at + size + 1] != 10) throw new IOException("Incomplete chunk");
            out.write(body, at, size);
            at += size + 2;
        }
        throw new IOException("Missing final chunk");
    }
}
