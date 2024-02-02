package uk.gov.di.ipv.core.processcricallback.pact;

import au.com.dius.pact.consumer.dsl.BodyBuilder;
import au.com.dius.pact.core.model.ContentType;
import au.com.dius.pact.core.model.generators.Generators;
import au.com.dius.pact.core.model.matchingrules.MatchingRuleCategory;
import au.com.dius.pact.core.model.matchingrules.MatchingRuleGroup;
import au.com.dius.pact.core.model.matchingrules.RegexMatcher;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.Base64URL;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

// This class can generate an example signed JWT for use in a test, but will also tell the PACT
// framework that the provider signature does not need to match the example signature (as JWT
// signatures are randomised)
public class PactJwtIgnoreSignatureBodyBuilder implements BodyBuilder {
    private final String minifiedHeaderJson;
    private final String minifiedBodyJson;
    private final String signature;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public PactJwtIgnoreSignatureBodyBuilder(String headerJson, String bodyJson, String signature) {
        this.minifiedHeaderJson = minifyJson(headerJson);
        this.minifiedBodyJson = minifyJson(bodyJson);
        this.signature = signature;
    }

    @Override
    public MatchingRuleCategory getMatchers() {
        var noSignatureRegex = new RegexMatcher(createJwtRegex());
        return new MatchingRuleCategory(
                "body", // This category is for the body of the response
                Collections.singletonMap(
                        // $ means that this rule is for the root of the body
                        "$", new MatchingRuleGroup(List.of(noSignatureRegex))));
    }

    @Override
    public Generators getGenerators() {
        return new Generators();
    }

    @Override
    public ContentType getContentType() {
        return new ContentType("application/jwt");
    }

    @Override
    public byte[] buildBody() {
        return (Base64URL.encode(minifiedHeaderJson)
                        + "."
                        + Base64URL.encode(minifiedBodyJson)
                        + "."
                        + signature)
                .getBytes(StandardCharsets.UTF_8);
    }

    private String createJwtRegex() {
        return "^"
                + Base64URL.encode(minifiedHeaderJson)
                + "\\."
                + Base64URL.encode(minifiedBodyJson)
                + "\\..*";
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
