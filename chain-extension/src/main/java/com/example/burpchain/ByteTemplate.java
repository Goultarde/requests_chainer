package com.example.burpchain;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Substitutes ASCII variable markers while preserving every other request byte. */
final class ByteTemplate {
    private static final Pattern VARIABLE = Pattern.compile("\\{\\{([A-Za-z][A-Za-z0-9_]*)}}");
    private static final Pattern LENGTH = Pattern.compile("(?im)^Content-Length:[ \\t]*[0-9]+[ \\t]*$");
    private ByteTemplate() {}

    static byte[] render(byte[] template, Map<String, String> values, Function<String, byte[]> encodeValue) {
        String view = new String(template, StandardCharsets.ISO_8859_1);
        Matcher marker = VARIABLE.matcher(view);
        if (!marker.find()) return template.clone();
        ByteArrayOutputStream out = new ByteArrayOutputStream(template.length);
        int position = 0;
        do {
            out.write(template, position, marker.start() - position);
            String value = values.get(marker.group(1));
            if (value == null) throw new IllegalArgumentException("Undefined variable: " + marker.group(1));
            out.writeBytes(encodeValue.apply(value));
            position = marker.end();
        } while (marker.find());
        out.write(template, position, template.length - position);
        byte[] rendered = out.toByteArray();
        String resultView = new String(rendered, StandardCharsets.ISO_8859_1);
        int separator = resultView.indexOf("\r\n\r\n");
        int newlineWidth = 2;
        if (separator < 0) { separator = resultView.indexOf("\n\n"); newlineWidth = 1; }
        if (separator < 0) return rendered;
        String headers = resultView.substring(0, separator);
        if (Pattern.compile("(?im)^Transfer-Encoding:[ \\t]*chunked[ \\t]*$").matcher(headers).find())
            return rendered;
        Matcher length = LENGTH.matcher(headers);
        if (!length.find()) return rendered;
        int bodyLength = rendered.length - separator - 2 * newlineWidth;
        int start = length.start();
        int end = length.end();
        if (length.find()) throw new IllegalArgumentException("Multiple Content-Length headers are unsupported");
        return ByteSplice.replace(rendered, start, end,
                ("Content-Length: " + bodyLength).getBytes(StandardCharsets.US_ASCII));
    }
}
