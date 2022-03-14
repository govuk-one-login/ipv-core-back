package uk.gov.di.ipv.core.credentialissuer;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialIssuerStartHandlerTest {

    public static final String CRI_ID = "PassportIssuer";
    public static final String CRI_NAME = "any";
    public static final String CRI_TOKEN_URL = "http://www.example.com";
    public static final String CRI_CREDENTIAL_URL = "http://www.example.com/credential";
    public static final String CRI_AUTHORIZE_URL = "http://www.example.com/authorize";
    public static final String IPV_CLIENT_ID = "ipv-core";
    private static final String SESSION_ID = UUID.randomUUID().toString();
    private static final String AUTHORIZATION_CODE = "bar";

    @Mock private Context context;

    @Mock ConfigurationService configurationService;

    private CredentialIssuerConfig credentialIssuerConfig;

    private CredentialIssuerStartHandler underTest;

    @BeforeEach
    void setUp() throws URISyntaxException {
        underTest = new CredentialIssuerStartHandler(configurationService);
        credentialIssuerConfig =
                new CredentialIssuerConfig(
                        CRI_ID,
                        CRI_NAME,
                        new URI(CRI_TOKEN_URL),
                        new URI(CRI_CREDENTIAL_URL),
                        new URI(CRI_AUTHORIZE_URL),
                        IPV_CLIENT_ID);
    }

    @Test
    void shouldReceive400ResponseCodeIfAuthorizationCodeNotPresent()
            throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of("credential_issuer_id", "foo"),
                        Map.of("ipv-session-id", SESSION_ID));
        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assert400Response(response, ErrorResponse.MISSING_AUTHORIZATION_CODE);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of("authorization_code", "foo"), Map.of("ipv-session-id", SESSION_ID));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
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
                        Map.of("ipv-session-id", SESSION_ID));
        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assert400Response(response, ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID);
    }

    @Test
    void shouldReceive400ResponseCodeIfSessionIdNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of("authorization_code", "foo", "credential_issuer_id", CRI_ID),
                        Map.of());
        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assert400Response(response, ErrorResponse.MISSING_IPV_SESSION_ID);
    }

    @Test
    void shouldReceive200ResponseCodeAndReturnCredentialIssuerResponse()
            throws JsonProcessingException {
        when(configurationService.getCredentialIssuer(CRI_ID)).thenReturn(credentialIssuerConfig);

        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                AUTHORIZATION_CODE,
                                "credential_issuer_id",
                                CRI_ID),
                        Map.of("ipv-session-id", SESSION_ID));
        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map responseBody = getResponseBodyAsMap(response);

        assertEquals(CRI_ID, responseBody.get("id"));
        assertEquals(CRI_AUTHORIZE_URL, responseBody.get("authorizeUrl"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
        verifyNoInteractions(context);
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
    }
}
