package uk.gov.di.ipv.core.library.pacttesthelpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.Base64URL;

public class PactJwtBuilder {
    private final String minifiedHeaderJson;
    private final String minifiedBodyJson;
    private final String signature;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public PactJwtBuilder(String headerJson, String bodyJson, String signature) {
        this.minifiedHeaderJson = minifyJson(headerJson);
        this.minifiedBodyJson = minifyJson(bodyJson);
        this.signature = signature;
    }

    public String buildJwt() {
        return Base64URL.encode(minifiedHeaderJson)
                + "."
                + Base64URL.encode(minifiedBodyJson)
                + "."
                + signature;
    }

    public String buildRegexMatcherIgnoringSignature() {
        return "^"
                + Base64URL.encode(minifiedHeaderJson)
                + "\\."
                + Base64URL.encode(minifiedBodyJson)
                + "\\..*";
    }

    // This is test code and any exception we throw will be caught by the test framework and fail
    // the test.
    @SuppressWarnings("java:S112")
    private String minifyJson(String prettyJson) {
        JsonNode jsonNode;
        try {
            jsonNode = objectMapper.readValue(prettyJson, JsonNode.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        return jsonNode.toString();
    }
}
