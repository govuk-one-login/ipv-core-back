package uk.gov.di.ipv.core.storetriagedata;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.service.ConfigService;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class StoreTriageDataHandlerTest {
    @Mock private Context context;
    @Mock private ConfigService mockConfigService;

    @InjectMocks private StoreTriageDataHandler handler;

    @Test
    void handleRequestShouldReturn200() {
        var request = new APIGatewayProxyRequestEvent();
        request.setBody("{}");

        APIGatewayProxyResponseEvent response = handler.handleRequest(request, context);

        assertEquals(200, response.getStatusCode());
    }
}
