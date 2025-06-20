package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.ipv.core.library.domain.EvidenceRequest;

import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CriStepResponseTest {

    @ParameterizedTest
    @MethodSource("journeyUriParameters")
    void valueReturnsExpectedJourneyResponse(
            String criId, String context, EvidenceRequest evidenceRequest, String expectedJourney) {
        CriStepResponse response = new CriStepResponse(criId, context, evidenceRequest);
        assertEquals(
                Map.of("journey", expectedJourney),
                response.value(),
                () ->
                        String.format(
                                "Expected journey for criId=%s, context=%s, evidenceRequest=%s was not as expected",
                                criId, context, evidenceRequest));
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
                        new EvidenceRequest("gpg45", 2, null, null),
                        "/journey/cri/build-oauth-request/aCriId?evidenceRequest=eyJzY29yaW5nUG9saWN5IjoiZ3BnNDUiLCJzdHJlbmd0aFNjb3JlIjoyfQ%3D%3D"),
                Arguments.of(
                        "aCriId",
                        "test_context",
                        new EvidenceRequest("gpg45", 2, null, null),
                        "/journey/cri/build-oauth-request/aCriId?context=test_context&evidenceRequest=eyJzY29yaW5nUG9saWN5IjoiZ3BnNDUiLCJzdHJlbmd0aFNjb3JlIjoyfQ%3D%3D"));
    }
}
