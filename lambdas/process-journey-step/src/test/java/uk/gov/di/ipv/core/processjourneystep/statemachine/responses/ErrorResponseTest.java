package uk.gov.di.ipv.core.processjourneystep.statemachine.responses;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

public class ErrorResponseTest {

    public static final ErrorResponse ERROR_RESPONSE = new ErrorResponse("aPageId", "500");

    @Test
    void valueWithStringReturnsCorrectResponse() {
        assertEquals(
                Map.of("type", "error", "page", "overriddenPageId", "statusCode", 500),
                ERROR_RESPONSE.value("overriddenPageId"));
    }

    @Test
    void valueWithConfigServiceReturnsCorrectResponse() {
        assertEquals(
                Map.of("type", "error", "page", "aPageId", "statusCode", 500),
                ERROR_RESPONSE.value(mock(ConfigService.class)));
    }
}
