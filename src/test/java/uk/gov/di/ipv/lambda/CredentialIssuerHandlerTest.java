package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.domain.CredentialIssuerException;
import uk.gov.di.ipv.domain.ErrorResponse;
import uk.gov.di.ipv.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.service.CredentialIssuerService;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialIssuerHandlerTest {

    @Mock
    private Context context;

    @Captor
    private ArgumentCaptor<CredentialIssuerRequestDto> requestDto;

    @Mock
    CredentialIssuerConfig passportIssuer;

    @Mock
    CredentialIssuerConfig fraudIssuer;

    @Mock
    CredentialIssuerService credentialIssuerService;

    String authorization_code = "bar";
    String sessionId = UUID.randomUUID().toString();
    String passportIssuerId = "PassportIssuerId";
    private Set<CredentialIssuerConfig> configs;

    @BeforeEach
    void setUp() {
        configs = Set.of(passportIssuer, fraudIssuer);
    }

    @Test
    void shouldReceive400ResponseCodeIfAuthorizationCodeNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = createRequestEvent("credential_issuer_id=foo&session_id=foo");
        APIGatewayProxyResponseEvent response = new CredentialIssuerHandler(credentialIssuerService, configs).handleRequest(input, context);
        assert400Response(response, ErrorResponse.MissingAuthorizationCode);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = createRequestEvent("authorization_code=bar&session_id=foo");
        APIGatewayProxyResponseEvent response = new CredentialIssuerHandler(credentialIssuerService, configs).handleRequest(input, context);
        assert400Response(response, ErrorResponse.MissingCredentialIssuerId);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotInPermittedSet() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = createRequestEvent("authorization_code=bar&credential_issuer_id=bar&session_id=foo");
        APIGatewayProxyResponseEvent response = new CredentialIssuerHandler(credentialIssuerService, configs).handleRequest(input, context);
        assert400Response(response, ErrorResponse.InvalidCredentialIssuerId);
    }

    @Test
    void shouldReceive400ResponseCodeIfSessionIdNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = createRequestEvent("authorization_code=bar&credential_issuer_id=PassportIssuer");
        APIGatewayProxyResponseEvent response = new CredentialIssuerHandler(credentialIssuerService, configs).handleRequest(input, context);
        assert400Response(response, ErrorResponse.MissingSessionId);
    }

    @Test
    void shouldReceive200ResponseCodeIfAllRequestParametersValid() {
        AccessToken accessToken = mock(AccessToken.class);

        when(credentialIssuerService.exchangeCodeForToken(
                requestDto.capture(),
                ArgumentMatchers.eq(passportIssuer))
        ).thenReturn(accessToken);
        when(passportIssuer.getId()).thenReturn(passportIssuerId);


        CredentialIssuerHandler handler = new CredentialIssuerHandler(credentialIssuerService, configs);
        APIGatewayProxyRequestEvent input = createRequestEvent(String.format("authorization_code=%s&credential_issuer_id=%s&session_id=%s", authorization_code, passportIssuerId, sessionId));

        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);

        Integer statusCode = response.getStatusCode();
        assertEquals(HTTPResponse.SC_OK, statusCode);
        CredentialIssuerRequestDto value = requestDto.getValue();
        assertEquals(sessionId, value.getSession_id());
        assertEquals(passportIssuerId, value.getCredential_issuer_id());
        assertEquals(authorization_code, value.getAuthorization_code());
        verifyNoInteractions(context);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerServiceThrowsException() throws JsonProcessingException {
        CredentialIssuerHandler handler = new CredentialIssuerHandler(credentialIssuerService, configs);
        APIGatewayProxyRequestEvent input = createRequestEvent(String.format("authorization_code=%s&credential_issuer_id=%s&session_id=%s", authorization_code, passportIssuerId, sessionId));

        when(credentialIssuerService.exchangeCodeForToken(requestDto.capture(), ArgumentMatchers.eq(passportIssuer)))
                .thenThrow(new CredentialIssuerException("code1: message1"));
        when(passportIssuer.getId()).thenReturn(passportIssuerId);

        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_BAD_REQUEST, statusCode);
        assertEquals(ErrorResponse.InvalidTokenRequest.getCode(), responseBody.get("code"));
        verifyNoInteractions(context);
    }

    private Map getResponseBodyAsMap(APIGatewayProxyResponseEvent response) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);
        return responseBody;
    }

    private APIGatewayProxyRequestEvent createRequestEvent(String s) {
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setBody(s);
        return input;
    }

    private void assert400Response(APIGatewayProxyResponseEvent response, ErrorResponse errorResponse) throws JsonProcessingException {
        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_BAD_REQUEST, statusCode);
        assertEquals(errorResponse.getCode(), responseBody.get("code"));
        verifyNoInteractions(context, credentialIssuerService);
    }
}
