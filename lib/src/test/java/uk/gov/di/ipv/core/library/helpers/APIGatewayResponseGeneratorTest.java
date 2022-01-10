package uk.gov.di.ipv.core.library.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

class APIGatewayResponseGeneratorTest {

    @Test
    void proxyJsonResponseRaises500IfInvalidJson() {
        // using a mock causes ObjectMapper().writeValueAsString() to throw a
        // JsonProcessingException
        Object stringMock = mock(Object.class);
        APIGatewayProxyResponseEvent response =
                ApiGatewayResponseGenerator.proxyJsonResponse(200, stringMock);
        assertEquals(500, response.getStatusCode());
    }
}
