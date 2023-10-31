package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CriStepResponseTest {

    public static final CriStepResponse CRI_RESPONSE = new CriStepResponse("aCriId", null);
    public static final CriStepResponse CRI_RESPONSE_WITH_CONTEXT =
            new CriStepResponse("aCriId", "someContext");

    @Test
    void valueReturnsCorrectJourneyResponse() {
        assertEquals(
                Map.of("journey", "/journey/cri/build-oauth-request/aCriId", "context", ""),
                CRI_RESPONSE.value());
    }

    @Test
    void valueReturnsJourneyResponseWithContextIfExists() {
        assertEquals(
                Map.of(
                        "journey",
                        "/journey/cri/build-oauth-request/aCriId",
                        "context",
                        "someContext"),
                CRI_RESPONSE_WITH_CONTEXT.value());
    }
}
