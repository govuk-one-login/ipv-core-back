package uk.gov.di.ipv.core.library.pacttesthelpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;

public class PactJwtBuilder {
    private final Base64URL base64Header;
    private final Base64URL base64Body;
    private final Base64URL base64Signature;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public PactJwtBuilder(String headerJson, String bodyJson, String signature) {
        this.base64Header = Base64URL.encode(minifyJson(headerJson));
        this.base64Body = Base64URL.encode(minifyJson(bodyJson));
        this.base64Signature = new Base64URL(signature);
    }

    public static PactJwtBuilder fromPath(String path) throws IOException {
        String headerJson = IOUtils.resourceToString(path + "/header.json", StandardCharsets.UTF_8);
        String bodyJson = IOUtils.resourceToString(path + "/body.json", StandardCharsets.UTF_8);
        String signature =
                IOUtils.resourceToString(path + "/signature", StandardCharsets.UTF_8).trim();

        return new PactJwtBuilder(headerJson, bodyJson, signature);
    }

    public String buildJwt() {
        return base64Header + "." + base64Body + "." + base64Signature;
    }

    public SignedJWT buildSignedJwt() throws ParseException {
        return new SignedJWT(base64Header, base64Body, base64Signature);
    }

    public String buildRegexMatcherIgnoringSignature() {
        return "^" + base64Header + "\\." + base64Body + "\\..*";
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
