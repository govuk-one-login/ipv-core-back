package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EvidenceRequestTest {
    @SuppressWarnings("java:S125") // Commented out code
    // {"scoringPolicy":"gpg45","strengthScore":2}
    private static final String BASE64_ENCODED_GPG45_STRENGTH_2 =
            // pragma: allowlist nextline secret
            "eyJzY29yaW5nUG9saWN5IjoiZ3BnNDUiLCJzdHJlbmd0aFNjb3JlIjoyfQ==";

    @SuppressWarnings("java:S125") // Commented out code
    // {"scoringPolicy":"gpg45","verificationScore":1}
    private static final String BASE64_ENCODED_GPG45_VERIFICATION_1 =
            // pragma: allowlist nextline secret
            "eyJzY29yaW5nUG9saWN5IjoiZ3BnNDUiLCJ2ZXJpZmljYXRpb25TY29yZSI6MX0=";

    @SuppressWarnings("java:S125") // Commented out code
    // {"scoringPolicy":"gpg45","identityFraudScore":1}
    private static final String BASE64_ENCODED_GPG45_IDENTITY_FRAUD_SCORE_1 =
            // pragma: allowlist nextline secret
            "eyJzY29yaW5nUG9saWN5IjoiZ3BnNDUiLCJpZGVudGl0eUZyYXVkU2NvcmUiOjF9";

    @SuppressWarnings("java:S125") // Commented out code
    // {"scoringPolicy":"gpg45","strengthScore":2,"verificationScore":1,"identityFraudScore":1}
    private static final String BASE64_ENCODED_GPG45_STRENGTH_2_VERIFICATION_1 =
            // pragma: allowlist nextline secret
            "eyJzY29yaW5nUG9saWN5IjoiZ3BnNDUiLCJzdHJlbmd0aFNjb3JlIjoyLCJ2ZXJpZmljYXRpb25TY29yZSI6MSwiaWRlbnRpdHlGcmF1ZFNjb3JlIjoxfQ==";

    private static Stream<Arguments> base64EncodingsAndValues() {
        return Stream.of(
                Arguments.of(BASE64_ENCODED_GPG45_STRENGTH_2, "gpg45", 2, null, null),
                Arguments.of(BASE64_ENCODED_GPG45_VERIFICATION_1, "gpg45", null, 1, null),
                Arguments.of(BASE64_ENCODED_GPG45_IDENTITY_FRAUD_SCORE_1, "gpg45", null, null, 1),
                Arguments.of(BASE64_ENCODED_GPG45_STRENGTH_2_VERIFICATION_1, "gpg45", 2, 1, 1));
    }

    @ParameterizedTest
    @MethodSource("base64EncodingsAndValues")
    void toBase64_whenCalled_ReturnsCorrectEncoding(
            String expectedResult,
            String scoringPolicy,
            Integer strengthScore,
            Integer verificationScore,
            Integer identityFraudScore)
            throws JsonProcessingException {
        // Arrange
        var underTest =
                new EvidenceRequest(
                        scoringPolicy, strengthScore, verificationScore, identityFraudScore);

        // Act
        var result = underTest.toBase64();

        // Assert
        assertEquals(expectedResult, result);
    }

    @ParameterizedTest
    @MethodSource("base64EncodingsAndValues")
    void fromBase64_whenCalledWithStrengthScore_ReturnsEvidenceRequest(
            String base64, String scoringPolicy, Integer strengthScore, Integer verificationScore)
            throws JsonProcessingException {
        // Act
        var result = EvidenceRequest.fromBase64(base64);

        // Assert
        assertEquals(scoringPolicy, result.getScoringPolicy());
        assertEquals(strengthScore, result.getStrengthScore());
        assertEquals(verificationScore, result.getVerificationScore());
    }

    @Test
    void toMapWithNoNulls_whenCalledWithAllNullValues_ReturnsEmptyMap() {
        // Arrange
        var underTest = new EvidenceRequest(null, null, null, null);

        // Act
        var result = underTest.toMapWithNoNulls();

        // Assert
        assertEquals(0, result.size());
    }

    @Test
    void toMapWithNoNulls_whenCalledWithNoNullValues_ReturnsFullMap() {
        // Arrange
        var underTest = new EvidenceRequest("policy", 1, 2, 1);

        // Act
        var result = underTest.toMapWithNoNulls();

        // Assert
        assertEquals("policy", result.get("scoringPolicy"));
        assertEquals(1, result.get("strengthScore"));
        assertEquals(2, result.get("verificationScore"));
        assertEquals(1, result.get("identityFraudScore"));
    }
}
