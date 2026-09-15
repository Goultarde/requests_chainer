package com.example.burpchain;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.nio.charset.StandardCharsets;

/** Explicit {{name}} placeholders are substituted in the complete raw request. */
public final class Template {
    private static final Pattern VARIABLE = Pattern.compile("\\{\\{([A-Za-z][A-Za-z0-9_]*)}}");
    private Template() {}

    public static String render(String raw, Map<String, String> values) {
        Matcher matcher = VARIABLE.matcher(raw);
        StringBuffer result = new StringBuffer();
        while (matcher.find()) {
            String name = matcher.group(1);
            String value = values.get(name);
            if (value == null) throw new IllegalArgumentException("Undefined variable: " + name);
            matcher.appendReplacement(result, Matcher.quoteReplacement(value));
        }
        matcher.appendTail(result);
        return result.toString();
    }

    public static String renderHttpRequest(String raw, Map<String, String> values) {
        String rendered = render(raw, values);
        int separator = rendered.indexOf("\r\n\r\n");
        String newline = "\r\n";
        if (separator < 0) { separator = rendered.indexOf("\n\n"); newline = "\n"; }
        if (separator < 0) return rendered;
        int bodyStart = separator + newline.length() * 2;
        String headers = rendered.substring(0, separator);
        String body = rendered.substring(bodyStart);
        if (Pattern.compile("(?im)^Transfer-Encoding:\\s*chunked\\s*$").matcher(headers).find()) return rendered;
        Matcher lengths = Pattern.compile("(?im)^Content-Length:[ \\t]*[0-9]+[ \\t]*$").matcher(headers);
        if (!lengths.find()) return rendered;
        int size = body.getBytes(StandardCharsets.UTF_8).length;
        StringBuffer fixed = new StringBuffer();
        lengths.appendReplacement(fixed, "Content-Length: " + size);
        if (lengths.find()) throw new IllegalArgumentException("Multiple Content-Length headers are unsupported");
        lengths.appendTail(fixed);
        return fixed + newline + newline + body;
    }
}
