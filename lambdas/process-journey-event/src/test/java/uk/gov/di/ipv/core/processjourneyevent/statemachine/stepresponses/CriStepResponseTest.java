package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CriStepResponseTest {

    @ParameterizedTest
    @MethodSource("journeyUriParameters")
    void valueReturnsExpectedJourneyResponse(
            String criId, String context, String scope, String expectedJourney) {
        CriStepResponse response = new CriStepResponse(criId, context, scope);
        assertEquals(
                Map.of("journey", expectedJourney),
                response.value(),
                () ->
                        String.format(
                                "Expected journey for criId=%s, context=%s, scope=%s was not as expected",
                                criId, context, scope));
    }

    private static Stream<Arguments> journeyUriParameters() {
        return Stream.of(
                Arguments.of("aCriId", null, null, "/journey/cri/build-oauth-request/aCriId"),
                Arguments.of(
                        "aCriId",
                        "test_context",
                        null,
                        "/journey/cri/build-oauth-request/aCriId?context=test_context"),
                Arguments.of(
                        "aCriId",
                        null,
                        "test_scope",
                        "/journey/cri/build-oauth-request/aCriId?scope=test_scope"),
                Arguments.of(
                        "aCriId",
                        "test_context",
                        "test_scope",
                        "/journey/cri/build-oauth-request/aCriId?context=test_context&scope=test_scope"));
    }
}
