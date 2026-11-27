package uk.gov.di.ipv.core.dynamicrouting;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.persistence.item.DynamicRoutingState;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DynamicRoutingHandlerTest {
    private static final String TEST_SESSION_ID = "test-session-id";

    @Mock private AuditService auditService;
    @Mock private ConfigService configService;
    @Mock private Context context;
    @Mock private IpvSessionService ipvSessionService;
    @InjectMocks private DynamicRoutingHandler handler;

    @Test
    void handleRequestShouldReturnNextJourney() throws IpvSessionNotFoundException {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setDynamicRoutingState(new DynamicRoutingState());
        when(ipvSessionService.getIpvSession(any())).thenReturn(ipvSessionItem);
        when(configService.getComponentId()).thenReturn("https://core-component.example");
        var request = ProcessRequest.processRequestBuilder().ipvSessionId(TEST_SESSION_ID).build();

        Map<String, Object> response = handler.handleRequest(request, context);

        assertEquals(new JourneyResponse("/journey/triage-uk").toObjectMap(), response);
    }
}
