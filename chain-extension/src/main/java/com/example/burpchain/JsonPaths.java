package com.example.burpchain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/** JSON Pointer paths avoid ambiguity when objects contain repeated field names. */
public final class JsonPaths {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private JsonPaths() {}

    public static List<String> pathsForValue(String json, String selectedValue) throws IOException {
        JsonNode root = MAPPER.readTree(json);
        if (root == null) throw new IOException("Empty JSON response");
        List<String> found = new ArrayList<>();
        find(root, "", selectedValue, found);
        return found;
    }

    private static void find(JsonNode node, String path, String value, List<String> found) {
        if (node.isValueNode()) {
            if (!node.isNull() && node.asText().equals(value)) found.add(path);
        } else if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                find(field.getValue(), path + "/" + escape(field.getKey()), value, found);
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) find(node.get(i), path + "/" + i, value, found);
        }
    }

    private static String escape(String segment) { return segment.replace("~", "~0").replace("/", "~1"); }

    public static String extract(String json, String pointer) throws IOException {
        JsonNode root = MAPPER.readTree(json);
        if (root == null) throw new IOException("Empty JSON response");
        JsonNode node = root.at(pointer);
        if (node.isMissingNode() || node.isNull() || !node.isValueNode())
            throw new IOException("Missing or non-scalar JSON value at " + pointer);
        return node.asText();
    }
}
