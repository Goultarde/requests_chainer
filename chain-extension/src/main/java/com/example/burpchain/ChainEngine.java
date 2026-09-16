package com.example.burpchain;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

/** Runs steps in order; each response contributes variables to later requests. */
public final class ChainEngine {
    public record Step(String template, Map<String, String> outputs) {}
    public record Response(int status, String body) {}
    @FunctionalInterface public interface Sender { Response send(int stepIndex, String request) throws Exception; }
    @FunctionalInterface public interface Reporter { void report(String message); }

    private ChainEngine() {}

    public static Map<String, String> run(List<Step> steps, Sender sender, Reporter reporter) throws Exception {
        Map<String, String> variables = new LinkedHashMap<>();
        for (int i = 0; i < steps.size(); i++) {
            Step step = steps.get(i);
            String request = Template.renderHttpRequest(step.template(), variables);
            Response response = sender.send(i, request);
            if (response == null) throw new IOException("Step " + (i + 1) + " returned no response");
            if (response.status() >= 400) throw new IOException("Step " + (i + 1) + " returned HTTP " + response.status());
            for (Map.Entry<String, String> output : step.outputs().entrySet()) {
                String value = extract(response.body(), output.getValue());
                variables.put(output.getKey(), value);
                reporter.report("Step " + (i + 1) + ": {{" + output.getKey() + "}} = " + value);
            }
            reporter.report("Step " + (i + 1) + ": HTTP " + response.status());
        }
        return variables;
    }

    static String extract(String body, String selector) throws Exception {
        if (selector.startsWith("regex:") || selector.startsWith("regexi:")) {
            boolean insensitive = selector.startsWith("regexi:");
            String expression = selector.substring(insensitive ? "regexi:".length() : "regex:".length());
            int flags = Pattern.DOTALL | (insensitive ? Pattern.CASE_INSENSITIVE : 0);
            Matcher matcher = Pattern.compile(expression, flags).matcher(body);
            if (!matcher.find()) throw new IOException("Regex did not match the response");
            String extracted = matcher.groupCount() > 0 ? matcher.group(1) : matcher.group();
            if (matcher.find()) throw new IOException("Regex is ambiguous: it matched more than one value");
            if (extracted == null || extracted.isEmpty()) throw new IOException("Regex capture group is empty");
            return extracted;
        }
        if (selector.startsWith("delim:")) {
            String[] encoded = selector.substring("delim:".length()).split("\\.", -1);
            if (encoded.length != 2) throw new IOException("Invalid start/end extractor");
            String prefix = new String(Base64.getUrlDecoder().decode(encoded[0]), StandardCharsets.UTF_8);
            String suffix = new String(Base64.getUrlDecoder().decode(encoded[1]), StandardCharsets.UTF_8);
            // Adapted from ExtendedMacro (MIT): locate the start string, then
            // locate the stop string in the remaining response text.
            int start = prefix.isEmpty() ? 0 : body.indexOf(prefix);
            if (start < 0) throw new IOException("Start expression did not match the response");
            start += prefix.length();
            int end = suffix.isEmpty() ? body.length() : body.indexOf(suffix, start);
            if (end < 0) throw new IOException("End expression did not match the response");
            String extracted = body.substring(start, end);
            if (extracted.isEmpty()) throw new IOException("Start/end extractor produced an empty value");
            return extracted;
        }
        // JSON pointers target the response body; regex and delimiter selectors above
        // intentionally receive the complete response so headers can be captured.
        return JsonPaths.extract(responseBody(body), selector);
    }

    private static String responseBody(String response) {
        int separator = response.indexOf("\r\n\r\n");
        if (separator >= 0) return response.substring(separator + 4);
        separator = response.indexOf("\n\n");
        return separator >= 0 ? response.substring(separator + 2) : response;
    }

}
