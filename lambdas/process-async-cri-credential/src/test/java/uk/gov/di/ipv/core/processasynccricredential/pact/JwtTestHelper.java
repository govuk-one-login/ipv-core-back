package uk.gov.di.ipv.core.processasynccricredential.pact;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.Base64URL;

public class JwtTestHelper {
    private final String minifiedHeaderJson;
    private final String minifiedBodyJson;
    private final String signature;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public JwtTestHelper(String headerJson, String bodyJson, String signature) {
        this.minifiedHeaderJson = minifyJson(headerJson);
        this.minifiedBodyJson = minifyJson(bodyJson);
        this.signature = signature;
    }

    public String build() {
        return Base64URL.encode(minifiedHeaderJson)
                + "."
                + Base64URL.encode(minifiedBodyJson)
                + "."
                + signature;
    }

    private String minifyJson(String prettyJson) {
        JsonNode jsonNode = null;
        try {
            jsonNode = objectMapper.readValue(prettyJson, JsonNode.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        return jsonNode.toString();
    }
}
