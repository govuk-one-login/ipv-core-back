package uk.gov.di.ipv.core.contraindicatorstoragecorestub;

import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.model.InvokeRequest;
import com.amazonaws.services.lambda.model.InvokeResult;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.ByteBuffer;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ContraIndicatorStorageCoreStubHandlerTest {

    @Mock AWSLambda awsLambdaClient;
    @Mock Context context;
    @InjectMocks ContraIndicatorStorageCoreStubHandler handler;

    @Test
    void itHandlesAPostRequest() {
        var event =
                new APIGatewayProxyRequestEvent()
                        .withHttpMethod("POST")
                        .withHeaders(Map.of("Host", "example.com"))
                        .withRequestContext(
                                new APIGatewayProxyRequestEvent.ProxyRequestContext()
                                        .withPath("/path/to/endpoint"))
                        .withBody("user-id=aUsersId&contra-indicators=X01");

        InvokeResult result =
                new InvokeResult().withPayload(ByteBuffer.allocate(0)).withStatusCode(200);
        when(awsLambdaClient.invoke(any(InvokeRequest.class))).thenReturn(result);
        var responseEvent = handler.handleRequest(event, context);

        assertEquals(
                "https://example.com/path/to/endpoint?userId=aUsersId",
                responseEvent.getHeaders().get("Location"));
        assertEquals(302, responseEvent.getStatusCode());
    }

    @Test
    void itHandlesAGetRequest() {
        var event =
                new APIGatewayProxyRequestEvent()
                        .withHttpMethod("GET")
                        .withRequestContext(
                                new APIGatewayProxyRequestEvent.ProxyRequestContext()
                                        .withPath("/path/to/endpoint"));
        var responseEvent = handler.handleRequest(event, context);

        assertEquals("text/html", responseEvent.getHeaders().get("Content-Type"));
        assertTrue(responseEvent.getBody().contains("Contra-indicator storage core stub"));
    }
}
