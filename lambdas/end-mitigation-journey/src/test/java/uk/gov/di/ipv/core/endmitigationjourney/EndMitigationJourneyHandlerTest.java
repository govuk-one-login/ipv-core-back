package uk.gov.di.ipv.core.endmitigationjourney;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class EndMitigationJourneyHandlerTest {
    @Mock private Context mockContext;

    @InjectMocks
    private EndMitigationJourneyHandler endMitigationJourneyHandler =
            new EndMitigationJourneyHandler();

    @Test
    void shouldReturnHelloWorld() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        APIGatewayProxyResponseEvent response =
                endMitigationJourneyHandler.handleRequest(event, mockContext);

        assertEquals("\"hello world\"", response.getBody());
    }
}
