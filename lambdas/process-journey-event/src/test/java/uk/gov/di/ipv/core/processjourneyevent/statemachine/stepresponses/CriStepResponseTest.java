package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CriStepResponseTest {

    public static final String CRI_SCOPE_VALUE = "criScope";
    public static final CriStepResponse CRI_RESPONSE =
            new CriStepResponse("aCriId", CRI_SCOPE_VALUE);

    @Test
    void valueReturnsCorrectJourneyResponse() {
        assertEquals(
                Map.of(
                        "journey",
                        "/journey/cri/build-oauth-request/aCriId",
                        "scope",
                        CRI_SCOPE_VALUE),
                CRI_RESPONSE.value());
    }
}
