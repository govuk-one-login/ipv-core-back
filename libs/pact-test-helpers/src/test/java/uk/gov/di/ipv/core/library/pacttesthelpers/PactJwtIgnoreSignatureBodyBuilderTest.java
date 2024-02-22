package uk.gov.di.ipv.core.library.pacttesthelpers;

import au.com.dius.pact.core.model.matchingrules.RegexMatcher;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class PactJwtIgnoreSignatureBodyBuilderTest {
    private final String JWT_HEADER =
            """
            {
              "alg": "ES256",
              "typ": "JWT"
            }
            """;

    private final String JWT_HEADER_BASE64 = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9";

    private final String JWT_BODY =
            """
            {
              "sub": "1234567890",
              "name": "John Doe"
            }
            """;

    private final String JWT_BODY_BASE64 = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0";

    @Test
    void buildBodyReturnsAValidExampleBody() {
        // Arrange
        var underTest = new PactJwtIgnoreSignatureBodyBuilder(JWT_HEADER, JWT_BODY, "signature");

        // Act
        var result = underTest.buildBody();

        // Assert
        assertArrayEquals(
                (JWT_HEADER_BASE64 + "." + JWT_BODY_BASE64 + ".signature")
                        .getBytes(StandardCharsets.UTF_8),
                result);
    }

    @Test
    void getMatchersReturnsARegexBodyMatcher() {
        // Arrange
        var underTest = new PactJwtIgnoreSignatureBodyBuilder(JWT_HEADER, JWT_BODY, "signature");

        // Act
        var result = underTest.getMatchers();

        // Assert
        assertEquals("body", result.getName());
        var rules = result.getMatchingRules().get("$").getRules();
        assertEquals(1, rules.size());
        assertEquals(
                ((RegexMatcher) rules.get(0)).getRegex(),
                "^" + JWT_HEADER_BASE64 + "\\." + JWT_BODY_BASE64 + "\\..*");
    }

    @Test
    void getGeneratorsReturnsEmtpySet() {
        // Arrange
        var underTest = new PactJwtIgnoreSignatureBodyBuilder(JWT_HEADER, JWT_BODY, "signature");

        // Act
        var result = underTest.getGenerators();

        // Assert
        assertTrue(result.isEmpty());
    }

    @Test
    void getContentTypeReturnsJwt() {
        // Arrange
        var underTest = new PactJwtIgnoreSignatureBodyBuilder(JWT_HEADER, JWT_BODY, "signature");

        // Act
        var result = underTest.getContentType();

        // Assert
        assertEquals("application/jwt", result.toString());
    }
}
