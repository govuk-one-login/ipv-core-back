package uk.gov.di.ipv.core.library.pacttesthelpers;

import au.com.dius.pact.consumer.dsl.BodyBuilder;
import au.com.dius.pact.core.model.ContentType;
import au.com.dius.pact.core.model.generators.Generators;
import au.com.dius.pact.core.model.matchingrules.MatchingRuleCategory;
import au.com.dius.pact.core.model.matchingrules.MatchingRuleGroup;
import au.com.dius.pact.core.model.matchingrules.RegexMatcher;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

// This class can generate an example signed JWT for use in a test, but will also tell the PACT
// framework that the provider signature does not need to match the example signature (as JWT
// signatures are randomised)
public class PactJwtIgnoreSignatureBodyBuilder implements BodyBuilder {
    private final PactJwtBuilder testHelper;

    public PactJwtIgnoreSignatureBodyBuilder(String headerJson, String bodyJson, String signature) {
        testHelper = new PactJwtBuilder(headerJson, bodyJson, signature);
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
        return (testHelper.buildJwt()).getBytes(StandardCharsets.UTF_8);
    }

    private String createJwtRegex() {
        return testHelper.buildRegexMatcherIgnoringSignature();
    }
}
