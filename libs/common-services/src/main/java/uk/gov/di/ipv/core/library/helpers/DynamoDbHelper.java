package uk.gov.di.ipv.core.library.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Stream;

public class DynamoDbHelper {
    private static final Logger LOGGER = LogManager.getLogger();

    private DynamoDbHelper() {
        throw new IllegalStateException("Helper class");
    }

    public static Map<String, Object> unmarshallLastEvaluatedKey(Map<String, AttributeValue> in) {
        Map<String, Object> out = new HashMap<>();
        if (in != null) {
            for (Map.Entry<String, AttributeValue> e : in.entrySet()) {
                Object uav = unwrapAttributeValue(e.getValue());
                if (uav != null) out.put(e.getKey(), uav);
            }
        }
        return out.isEmpty() ? null : out;
    }

    public static Map<String, AttributeValue> marshallToLastEvaluatedKey(Map<String, Object> in) {
        Map<String, AttributeValue> out = new HashMap<>();
        if (in != null) {
            for (Map.Entry<String, Object> e : in.entrySet()) {
                Object value = e.getValue();
                if (value instanceof String valStr) {
                    out.put(e.getKey(), AttributeValue.builder().s(valStr).build());
                } else if (value instanceof Number valNbr) {
                    out.put(e.getKey(), AttributeValue.builder().n(String.valueOf(valNbr)).build());
                } else if (value instanceof LinkedHashMap) {
                    marshallLinkedHashMapValue(out, e, (LinkedHashMap<String, String>) value);
                } else {
                    LOGGER.info(
                            LogHelper.buildLogMessage(
                                    "Not able to marshall it to lastEvaluateKey for scan."));
                }
            }
        }
        return out.isEmpty() ? null : out;
    }

    private static void marshallLinkedHashMapValue(
            Map<String, AttributeValue> out,
            Map.Entry<String, Object> e,
            LinkedHashMap<String, String> value) {
        var stringStringLinkedHashMap = value;
        String[] aKeys =
                stringStringLinkedHashMap
                        .keySet()
                        .toArray(new String[stringStringLinkedHashMap.size()]);
        if (aKeys.length == 1) {
            String linkedHashMapKeyValue = stringStringLinkedHashMap.get(aKeys[0]);
            if (aKeys[0].equals("S")) {
                out.put(e.getKey(), AttributeValue.builder().s(linkedHashMapKeyValue).build());
            } else if (aKeys[0].equals("N")) {
                out.put(e.getKey(), AttributeValue.builder().n(linkedHashMapKeyValue).build());
            } else if (aKeys[0].equals("BOOL")) {
                out.put(
                        e.getKey(),
                        AttributeValue.builder()
                                .bool(Boolean.valueOf(linkedHashMapKeyValue))
                                .build());
            }
        }
    }

    private static Object unwrapAttributeValue(AttributeValue av) {
        if (av.nul() != null && av.nul()) return null;
        if (av.m() != null && !av.m().isEmpty()) return unmarshallLastEvaluatedKey(av.m());
        if (av.l() != null && !av.l().isEmpty())
            return av.l().stream().map(DynamoDbHelper::unwrapAttributeValue).toList();
        return Stream.<Function<AttributeValue, Object>>of(
                        AttributeValue::s,
                        AttributeValue::n,
                        AttributeValue::bool,
                        AttributeValue::ns,
                        AttributeValue::ss,
                        AttributeValue::b,
                        AttributeValue::bs)
                .map(f -> f.apply(av))
                .filter(Objects::nonNull)
                .findFirst()
                .orElseThrow();
    }
}
