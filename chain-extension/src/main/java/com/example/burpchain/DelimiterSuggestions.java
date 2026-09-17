package com.example.burpchain;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Suggests response boundaries for a selected value. */
final class DelimiterSuggestions {
    private DelimiterSuggestions() {}

    static String[] bestDelimiters(String response, String value, int preferredAt) {
        int at = preferredAt >= 0 && response.startsWith(value, preferredAt)
                ? preferredAt : response.indexOf(value);
        if (at < 0 || value.isEmpty()) return defaultDelimiters(response, value);
        int before = Math.max(0, at - 8);
        int after = Math.min(response.length(), at + value.length() + 8);
        while (true) {
            int cleanBefore = before;
            while (cleanBefore < at && Character.isWhitespace(response.charAt(cleanBefore))) cleanBefore++;
            String prefix = response.substring(cleanBefore, at);
            String suffix = response.substring(at + value.length(), after);
            Matcher match = Pattern.compile(Pattern.quote(prefix) + "(.*?)" + Pattern.quote(suffix),
                    Pattern.DOTALL).matcher(response);
            if (match.find() && match.start(1) == at && match.end(1) == at + value.length()
                    && !match.find()) return new String[]{prefix, suffix};
            int oldBefore = before;
            int oldAfter = after;
            before = Math.max(0, before - 8);
            after = Math.min(response.length(), after + 8);
            if (before == oldBefore && after == oldAfter) break;
        }
        return defaultDelimiters(response, value);
    }

    static String defaultRegex(String prefix, String suffix) {
        return escapeRegex(prefix) + "(.*?)" + escapeRegex(suffix);
    }

    private static String escapeRegex(String value) {
        return value.replaceAll("([\\\\.\\[\\]{}()*+?^$|])", "\\\\$1");
    }

    private static String[] defaultDelimiters(String body, String value) {
        int at = body.indexOf(value);
        if (at < 0) return new String[]{"", ""};
        int line = Math.max(body.lastIndexOf("\n", at), body.lastIndexOf("\r", at));
        int semi = body.lastIndexOf(';', at);
        int start;
        if (semi < line) {
            start = line + 1;
        } else {
            start = semi + 1;
            while (start < at && Character.isWhitespace(body.charAt(start))) start++;
        }
        String prefix = body.substring(start, at);
        int lineEnd = body.indexOf('\n', at + value.length());
        if (lineEnd < 0) lineEnd = body.length();
        int contentEnd = lineEnd > 0 && body.charAt(lineEnd - 1) == '\r' ? lineEnd - 1 : lineEnd;
        int end = body.indexOf(';', at + value.length());
        if (end < 0 || end > lineEnd) end = -1;
        String suffix;
        if (end >= 0) {
            int equals = body.indexOf('=', end + 1);
            suffix = equals >= 0 ? body.substring(end, equals + 1) : body.substring(end);
        } else {
            suffix = body.substring(at + value.length(), contentEnd);
        }
        return new String[]{prefix, suffix};
    }
}
