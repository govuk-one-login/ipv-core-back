package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class ErrorResponseTest {
    @Test
    void errorCodesShouldIncreaseForErrorResponses() {
        // Arrange
        var errorResponses = ErrorResponse.values();
        var previousCode = 0;

        // Act & Assert
        for (var errorResponse : errorResponses) {
            assertTrue(
                    errorResponse.getCode() > previousCode,
                    String.format(
                            "Error response with code %s is not an increase from the previous code %s",
                            errorResponse.getCode(), previousCode));
            previousCode = errorResponse.getCode();
        }
    }
}
