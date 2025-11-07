package de.usd.cstchef.operations.vietjetair;

import burp.api.montoya.core.ByteArray;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

@OperationInfos(name = "API - Calculate Hash Request", category = OperationCategory.VIETJETAIR, description = "Calculate Hash Request")
public class CalculateHashRequest extends Operation {

    public static JsonNode sortKeys(JsonNode node) {
        if (node == null || node.isNull() || node.isValueNode()) {
            return node;
        }
        if (node.isArray()) {
            ArrayNode sortedArray = JsonNodeFactory.instance.arrayNode();
            for (JsonNode element : node) {
                sortedArray.add(sortKeys(element));
            }
            return sortedArray;
        }
        if (node.isObject()) {
            ObjectNode sortedObject = JsonNodeFactory.instance.objectNode();
            SortedSet<String> fieldNames = new TreeSet<>();
            node.fieldNames().forEachRemaining(fieldNames::add); // sắp xếp theo chữ cái

            for (String fieldName : fieldNames) {
                sortedObject.set(fieldName, sortKeys(node.get(fieldName)));
            }
            return sortedObject;
        }

        return node;
    }

    public static String jsonToQuery(JsonNode node, String prefix) {
        List<String> parts = new ArrayList<>();

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String key = entry.getKey();
                JsonNode value = entry.getValue();

                String newPrefix = (prefix != null && !prefix.isEmpty())
                        ? prefix + "[" + key + "]"
                        : key;

                parts.add(jsonToQuery(value, newPrefix));
            }
        } else if (node.isArray()) {
            for (JsonNode value : node) {
                parts.add(jsonToQuery(value, prefix));
            }
        } else {
            parts.add(safeQuote(prefix) + "=" + safeQuote(node.asText()));
        }
        return String.join("&", parts.stream().filter(p -> !p.isEmpty()).toList());
    }

    private static String safeQuote(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replaceAll("\\+", "%20");
    }

    public static String sha256Hash(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        String body = new String(input.getBytes(), StandardCharsets.UTF_8);
        body = body.replaceAll("null", "\"\"");
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonObject = mapper.readTree(body);
        ((ObjectNode)jsonObject).remove("_signature");
        JsonNode sortedJson = sortKeys(jsonObject);
        String queryString = jsonToQuery(sortedJson, "").replaceAll("None", "");
        ((ObjectNode) jsonObject).put("_signature", sha256Hash(queryString));
        return factory.createByteArray(mapper.writeValueAsString(jsonObject).getBytes());
    }
}