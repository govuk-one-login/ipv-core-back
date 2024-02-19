package uk.gov.di.ipv.core.library.pacttesthelpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class PactJwtBuilderTest {

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
    void buildJwtPutsPartsTogetherCorrectly() {
        // Arrange
        var underTest = new PactJwtBuilder(JWT_HEADER, JWT_BODY, "signature");

        // Act
        var result = underTest.buildJwt();

        // Assert
        assertEquals((JWT_HEADER_BASE64 + "." + JWT_BODY_BASE64 + ".signature"), result);
    }

    @Test
    void buildRegexMatcherIgnoringSignaturePutsPartsTogetherCorrectly() {
        // Arrange
        var underTest = new PactJwtBuilder(JWT_HEADER, JWT_BODY, "signature");

        // Act
        var result = underTest.buildRegexMatcherIgnoringSignature();

        // Assert
        assertEquals("^" + JWT_HEADER_BASE64 + "\\." + JWT_BODY_BASE64 + "\\..*", result);
    }
}
