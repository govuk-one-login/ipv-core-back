package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.domain.ErrorResponse;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

class CredentialIssuerHandlerTest {
    @Test
    void shouldReceive400ResponseCodeIfAuthorizationCodeNotPresent() throws JsonProcessingException {

        CredentialIssuerHandler handler = new CredentialIssuerHandler();
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();

        input.setBody("credential_issuer_id=foo");
        Context context = mock(Context.class);
        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_BAD_REQUEST, statusCode);
        assertEquals(ErrorResponse.MissingAuthorizationCode.getCode(), responseBody.get("code"));
        verifyNoInteractions(context);

    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotPresent() throws JsonProcessingException {

        CredentialIssuerHandler handler = new CredentialIssuerHandler();
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setBody("authorization_code=bar");

        Context context = mock(Context.class);
        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_BAD_REQUEST, statusCode);
        assertEquals(ErrorResponse.MissingCredentialIssuerId.getCode(), responseBody.get("code"));
        verifyNoInteractions(context);

    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotInPermittedSet() throws JsonProcessingException {

        CredentialIssuerHandler handler = new CredentialIssuerHandler();
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();

        input.setBody("authorization_code=bar&credential_issuer_id=barx");
        Context context = mock(Context.class);
        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_BAD_REQUEST, statusCode);
        assertEquals(ErrorResponse.InvalidCredentialIssuerId.getCode(), responseBody.get("code"));
        verifyNoInteractions(context);

    }

    @Test
    void shouldReceive200ResponseCodeIfAllRequestParametersValid() throws JsonProcessingException {

        CredentialIssuerHandler handler = new CredentialIssuerHandler();
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();

        input.setBody("authorization_code=bar&credential_issuer_id=PassportIssuer");
        Context context = mock(Context.class);
        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        Integer statusCode = response.getStatusCode();
        assertEquals(HTTPResponse.SC_OK, statusCode);
        verifyNoInteractions(context);

    }

    private Map getResponseBodyAsMap(APIGatewayProxyResponseEvent response) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);
        return responseBody;
    }
}
