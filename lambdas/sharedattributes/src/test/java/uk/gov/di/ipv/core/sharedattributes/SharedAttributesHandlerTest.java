package uk.gov.di.ipv.core.sharedattributes;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class SharedAttributesHandlerTest {

    @Mock private Context context;

    @Test
    void shouldExtractSessionIdFromHeaderAndReturnOK() {
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("ipv-session-id", "the-session-id"));
        SharedAttributesHandler handler = new SharedAttributesHandler();
        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        assertEquals(200, response.getStatusCode());
    }

    @Test
    void shouldReturnBadRequestIfSessionIdIsNotInTheHeader() {
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("not-ipv-session-header", "dummy-value"));
        SharedAttributesHandler handler = new SharedAttributesHandler();
        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        assertEquals(400, response.getStatusCode());
        assertEquals("ipv-session-id not present in header", response.getBody());
    }
}
