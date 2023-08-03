package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CriStepResponseTest {

    public static final CriStepResponse CRI_RESPONSE = new CriStepResponse("aCriId");

    @Test
    void valueReturnsCorrectJourneyResponse() {
        assertEquals(
                Map.of("journey", "/journey/cri/build-oauth-request/aCriId"), CRI_RESPONSE.value());
    }
}
