package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.domain.CredentialIssuerException;
import uk.gov.di.ipv.domain.ErrorResponse;
import uk.gov.di.ipv.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.service.CredentialIssuerService;

import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

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
    CredentialIssuerService credentialIssuerService;

    String authorization_code = "bar";
    String sessionId = UUID.randomUUID().toString();
    String passportIssuerId = "PassportIssuer";

    @Test
    void shouldReceive400ResponseCodeIfAuthorizationCodeNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = createRequestEvent(
                Map.of("credential_issuer_id", "foo"),
                Map.of("ipv-session-id", sessionId));
        APIGatewayProxyResponseEvent response = new CredentialIssuerHandler(credentialIssuerService).handleRequest(input, context);
        assert400Response(response, ErrorResponse.MissingAuthorizationCode);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = createRequestEvent(
                Map.of("authorization_code", "foo"),
                Map.of("ipv-session-id", sessionId));

        APIGatewayProxyResponseEvent response = new CredentialIssuerHandler(credentialIssuerService).handleRequest(input, context);
        assert400Response(response, ErrorResponse.MissingCredentialIssuerId);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotInPermittedSet() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = createRequestEvent(
                Map.of("authorization_code", "foo", "credential_issuer_id", "an invalid id"),
                Map.of("ipv-session-id", sessionId));
        APIGatewayProxyResponseEvent response = new CredentialIssuerHandler(credentialIssuerService).handleRequest(input, context);
        assert400Response(response, ErrorResponse.InvalidCredentialIssuerId);
    }

    @Test
    void shouldReceive400ResponseCodeIfSessionIdNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = createRequestEvent(
                Map.of("authorization_code", "foo", "credential_issuer_id", passportIssuerId),
                Map.of());
        APIGatewayProxyResponseEvent response = new CredentialIssuerHandler(credentialIssuerService).handleRequest(input, context);
        assert400Response(response, ErrorResponse.MissingSessionId);
    }

    @Test
    void shouldReceive200ResponseCodeIfAllRequestParametersValid() {
        AccessToken accessToken = mock(AccessToken.class);

        when(credentialIssuerService.exchangeCodeForToken(
                requestDto.capture(),
                ArgumentMatchers.eq(CredentialIssuerHandler.PASSPORT_ISSUER))
        ).thenReturn(accessToken);

        CredentialIssuerHandler handler = new CredentialIssuerHandler(credentialIssuerService);
        APIGatewayProxyRequestEvent input = createRequestEvent(
                Map.of("authorization_code", authorization_code, "credential_issuer_id", passportIssuerId),
                Map.of("ipv-session-id", sessionId));
        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);

        Integer statusCode = response.getStatusCode();
        assertEquals(HTTPResponse.SC_OK, statusCode);
        CredentialIssuerRequestDto value = requestDto.getValue();
        assertEquals(sessionId, value.getIpvSessionId());
        assertEquals(passportIssuerId, value.getCredentialIssuerId());
        assertEquals(authorization_code, value.getAuthorizationCode());
        verifyNoInteractions(context);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerServiceThrowsException() throws JsonProcessingException {
        CredentialIssuerHandler handler = new CredentialIssuerHandler(credentialIssuerService);
        APIGatewayProxyRequestEvent input = createRequestEvent(
                Map.of("authorization_code", "foo", "credential_issuer_id", passportIssuerId),
                Map.of("ipv-session-id", sessionId));

        when(credentialIssuerService.exchangeCodeForToken(requestDto.capture(), ArgumentMatchers.eq(CredentialIssuerHandler.PASSPORT_ISSUER)))
                .thenThrow(new CredentialIssuerException("code1: message1"));

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

    private APIGatewayProxyRequestEvent createRequestEvent(Map<String, String> body, Map<String, String> headers) {
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setBody(body.keySet().stream()
                .map(key -> key + "=" + body.get(key))
                .collect(Collectors.joining("&")));
        input.setHeaders(headers);
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
