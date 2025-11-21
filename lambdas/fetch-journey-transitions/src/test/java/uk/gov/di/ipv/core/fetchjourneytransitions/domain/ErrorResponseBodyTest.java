package uk.gov.di.ipv.core.fetchjourneytransitions.domain;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ErrorResponseBodyTest {
    @Test
    void shouldSerialiseAllFields() {
        // Arrange
        var body = new ErrorResponseBody("test message", ErrorCode.UNEXPECTED_ERROR);

        // Act
        var result = body.toString();

        // Assert
        assertEquals("{\"message\":\"test message\",\"code\":0}", result);
    }

    @Test
    void shouldIgnoreMissingErrorCode() {
        // Arrange
        var body = new ErrorResponseBody("test message");

        // Act
        var result = body.toString();

        // Assert
        assertEquals("{\"message\":\"test message\"}", result);
    }
}
