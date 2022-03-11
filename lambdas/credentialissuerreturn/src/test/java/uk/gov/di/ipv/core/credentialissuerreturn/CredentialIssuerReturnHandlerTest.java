package uk.gov.di.ipv.core.credentialissuerreturn;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.CredentialIssuerService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialIssuerReturnHandlerTest {

    @Mock private Context context;

    @Captor private ArgumentCaptor<CredentialIssuerRequestDto> requestDto;

    @Mock CredentialIssuerService credentialIssuerService;

    @Mock ConfigurationService configurationService;

    String authorization_code = "bar";
    String sessionId = UUID.randomUUID().toString();
    String passportIssuerId = "PassportIssuer";
    CredentialIssuerConfig passportIssuer;

    @BeforeEach
    void setUp() throws URISyntaxException {
        passportIssuer =
                new CredentialIssuerConfig(
                        "PassportIssuer",
                        "any",
                        new URI("http://www.example.com"),
                        new URI("http://www.example.com/credential"),
                        new URI("http://www.example.com/authorize"),
                        "ipv-core");
    }

    @Test
    void shouldReceive200AndJourneyResponseOnSuccessfulRequest() throws JsonProcessingException {
        CredentialIssuerReturnHandler handler =
                new CredentialIssuerReturnHandler(credentialIssuerService, configurationService);
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                "foo",
                                "credential_issuer_id",
                                passportIssuerId),
                        Map.of("ipv-session-id", sessionId));

        JSONObject testCredential = new JSONObject();
        testCredential.appendField("foo", "bar");

        when(credentialIssuerService.exchangeCodeForToken(requestDto.capture(), eq(passportIssuer)))
                .thenReturn(new BearerAccessToken());

        when(credentialIssuerService.getCredential(any(), any())).thenReturn(testCredential);

        when(configurationService.getCredentialIssuer("PassportIssuer")).thenReturn(passportIssuer);

        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_OK, statusCode);
        assertEquals("/journey/next", responseBody.get("journey"));
    }

    @Test
    void shouldReceive400ResponseCodeIfAuthorizationCodeNotPresent()
            throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of("credential_issuer_id", "foo"), Map.of("ipv-session-id", sessionId));
        APIGatewayProxyResponseEvent response =
                new CredentialIssuerReturnHandler(credentialIssuerService, configurationService)
                        .handleRequest(input, context);
        assert400Response(response, ErrorResponse.MISSING_AUTHORIZATION_CODE);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of("authorization_code", "foo"), Map.of("ipv-session-id", sessionId));

        APIGatewayProxyResponseEvent response =
                new CredentialIssuerReturnHandler(credentialIssuerService, configurationService)
                        .handleRequest(input, context);
        assert400Response(response, ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotInPermittedSet()
            throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                "foo",
                                "credential_issuer_id",
                                "an invalid id"),
                        Map.of("ipv-session-id", sessionId));
        APIGatewayProxyResponseEvent response =
                new CredentialIssuerReturnHandler(credentialIssuerService, configurationService)
                        .handleRequest(input, context);
        assert400Response(response, ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID);
    }

    @Test
    void shouldReceive400ResponseCodeIfSessionIdNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                "foo",
                                "credential_issuer_id",
                                passportIssuerId),
                        Map.of());
        APIGatewayProxyResponseEvent response =
                new CredentialIssuerReturnHandler(credentialIssuerService, configurationService)
                        .handleRequest(input, context);
        assert400Response(response, ErrorResponse.MISSING_IPV_SESSION_ID);
    }

    @Test
    void shouldReceive200ResponseCodeIfAllRequestParametersValid() {
        BearerAccessToken accessToken = mock(BearerAccessToken.class);

        when(credentialIssuerService.exchangeCodeForToken(requestDto.capture(), eq(passportIssuer)))
                .thenReturn(accessToken);

        when(credentialIssuerService.getCredential(accessToken, passportIssuer))
                .thenReturn(new JSONObject());

        when(configurationService.getCredentialIssuer("PassportIssuer")).thenReturn(passportIssuer);

        CredentialIssuerReturnHandler handler =
                new CredentialIssuerReturnHandler(credentialIssuerService, configurationService);
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                authorization_code,
                                "credential_issuer_id",
                                passportIssuerId),
                        Map.of("ipv-session-id", sessionId));
        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);

        CredentialIssuerRequestDto value = requestDto.getValue();
        assertEquals(sessionId, value.getIpvSessionId());
        assertEquals(passportIssuerId, value.getCredentialIssuerId());
        assertEquals(authorization_code, value.getAuthorizationCode());

        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());

        verifyNoInteractions(context);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerServiceThrowsException()
            throws JsonProcessingException {
        CredentialIssuerReturnHandler handler =
                new CredentialIssuerReturnHandler(credentialIssuerService, configurationService);
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                "foo",
                                "credential_issuer_id",
                                passportIssuerId),
                        Map.of("ipv-session-id", sessionId));

        when(credentialIssuerService.exchangeCodeForToken(requestDto.capture(), eq(passportIssuer)))
                .thenThrow(
                        new CredentialIssuerException(
                                HTTPResponse.SC_BAD_REQUEST, ErrorResponse.INVALID_TOKEN_REQUEST));

        when(configurationService.getCredentialIssuer("PassportIssuer")).thenReturn(passportIssuer);

        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_BAD_REQUEST, statusCode);
        assertEquals(ErrorResponse.INVALID_TOKEN_REQUEST.getCode(), responseBody.get("code"));
        verifyNoInteractions(context);
    }

    @Test
    void shouldReturn500IfCredentialIssuerServiceGetCredentialThrows()
            throws JsonProcessingException {
        when(credentialIssuerService.exchangeCodeForToken(any(), any()))
                .thenReturn(new BearerAccessToken());
        when(credentialIssuerService.getCredential(any(), any()))
                .thenThrow(
                        new CredentialIssuerException(
                                HTTPResponse.SC_SERVER_ERROR,
                                ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER));

        when(configurationService.getCredentialIssuer("PassportIssuer")).thenReturn(passportIssuer);

        CredentialIssuerReturnHandler handler =
                new CredentialIssuerReturnHandler(credentialIssuerService, configurationService);
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                authorization_code,
                                "credential_issuer_id",
                                passportIssuerId),
                        Map.of("ipv-session-id", sessionId));
        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);

        assertEquals(HTTPResponse.SC_SERVER_ERROR, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER.getCode(),
                getResponseBodyAsMap(response).get("code"));
    }

    private Map getResponseBodyAsMap(APIGatewayProxyResponseEvent response)
            throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(response.getBody(), Map.class);
    }

    private APIGatewayProxyRequestEvent createRequestEvent(
            Map<String, String> body, Map<String, String> headers) {
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setBody(
                body.keySet().stream()
                        .map(key -> key + "=" + body.get(key))
                        .collect(Collectors.joining("&")));
        input.setHeaders(headers);
        return input;
    }

    private void assert400Response(
            APIGatewayProxyResponseEvent response, ErrorResponse errorResponse)
            throws JsonProcessingException {
        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_BAD_REQUEST, statusCode);
        assertEquals(errorResponse.getCode(), responseBody.get("code"));
        verifyNoInteractions(context, credentialIssuerService);
    }
}
