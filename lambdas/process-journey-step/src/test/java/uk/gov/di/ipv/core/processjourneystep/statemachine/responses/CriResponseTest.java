package uk.gov.di.ipv.core.processjourneystep.statemachine.responses;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

public class CriResponseTest {

    public static final CriResponse CRI_RESPONSE = new CriResponse("aCriId");

    @Test
    void valueWithConfigServiceReturnsCorrectJourneyResponse() {
        assertEquals(
                Map.of("journey", "/journey/cri/build-oauth-request/aCriId"),
                CRI_RESPONSE.value(mock(ConfigService.class)));
    }

    @Test
    void valueWithStringReturnsCorrectJourneyResponse() {
        assertEquals(Map.of("journey", "overriddenCriId"), CRI_RESPONSE.value("overriddenCriId"));
    }
}
