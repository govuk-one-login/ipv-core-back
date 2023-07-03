package uk.gov.di.ipv.core.processjourneystep.statemachine.responses;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

public class PageResponseTest {

    public static final PageResponse PAGE_RESPONSE = new PageResponse("aPageId");

    @Test
    void valueWithConfigServiceReturnsCorrectPageResponse() {
        assertEquals(Map.of("page", "aPageId"), PAGE_RESPONSE.value(mock(ConfigService.class)));
    }

    @Test
    void valueWithStringReturnsCorrectPageResponse() {
        assertEquals(Map.of("page", "overriddenPageId"), PAGE_RESPONSE.value("overriddenPageId"));
    }
}
