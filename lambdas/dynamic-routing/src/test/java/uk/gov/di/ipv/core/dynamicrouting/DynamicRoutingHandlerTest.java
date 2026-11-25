package uk.gov.di.ipv.core.dynamicrouting;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NEXT_PATH;

@ExtendWith(MockitoExtension.class)
class DynamicRoutingHandlerTest {
    private static final String TEST_SESSION_ID = "test-session-id";

    @Mock private ConfigService configService;
    @Mock private Context context;
    @InjectMocks private DynamicRoutingHandler handler;

    @Test
    void handleRequestShouldReturnNextJourney() {
        when(configService.getComponentId()).thenReturn("https://core-component.example");
        var request = ProcessRequest.processRequestBuilder().ipvSessionId(TEST_SESSION_ID).build();

        Map<String, Object> response = handler.handleRequest(request, context);

        assertEquals(new JourneyResponse(JOURNEY_NEXT_PATH).toObjectMap(), response);
    }
}
