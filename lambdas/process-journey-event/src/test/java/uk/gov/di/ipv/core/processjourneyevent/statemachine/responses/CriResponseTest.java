package uk.gov.di.ipv.core.processjourneyevent.statemachine.responses;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CriResponseTest {

    public static final CriResponse CRI_RESPONSE = new CriResponse("aCriId");

    @Test
    void valueReturnsCorrectJourneyResponse() {
        assertEquals(
                Map.of("journey", "/journey/cri/build-oauth-request/aCriId"), CRI_RESPONSE.value());
    }
}
