package uk.gov.di.ipv.core.journeyengine;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNull;

class JourneyEngineHandlerTest {
    @Mock private Context mockContext;

    private JourneyEngineHandler journeyEngineHandler;

    @BeforeEach
    void setUp() {
        journeyEngineHandler = new JourneyEngineHandler();
    }

    @Test
    void shouldReturnNull() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyId", "next");
        event.setPathParameters(pathParameters);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        assertNull(response);
    }
}
