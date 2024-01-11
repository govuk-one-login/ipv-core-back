package uk.gov.di.ipv.core.processasynccricredential.pact;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.Base64URL;

// This class can generate an example signed JWT for use in a test, but will also tell the PACT
// framework that the provider signature does not need to match the example signature (as JWT
// signatures are randomised)
public class JwtBuilder {
    private final String minifiedHeaderJson;
    private final String minifiedBodyJson;
    private final String signature;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public JwtBuilder(String headerJson, String bodyJson, String signature) {
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
