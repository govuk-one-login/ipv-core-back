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
class JourneyCriStartHandlerTest {

    @Mock private Context context;

    @Mock ConfigurationService configurationService;

    private final String authorization_code = "bar";
    private final String sessionId = UUID.randomUUID().toString();
    private final String passportIssuerId = "PassportIssuer";
    private CredentialIssuerConfig passportIssuer;

    private JourneyCriStartHandler underTest;

    @BeforeEach
    void setUp() throws URISyntaxException {
        underTest = new JourneyCriStartHandler(configurationService);
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
    void shouldReceive400ResponseCodeIfAuthorizationCodeNotPresent()
            throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of("credential_issuer_id", "foo"), Map.of("ipv-session-id", sessionId));
        APIGatewayProxyResponseEvent response =
                underTest
                        .handleRequest(input, context);
        assert400Response(response, ErrorResponse.MISSING_AUTHORIZATION_CODE);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of("authorization_code", "foo"), Map.of("ipv-session-id", sessionId));

        APIGatewayProxyResponseEvent response =
                underTest
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
                underTest
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
                underTest
                        .handleRequest(input, context);
        assert400Response(response, ErrorResponse.MISSING_IPV_SESSION_ID);
    }

    @Test
    void shouldReceive200ResponseCodeIfAllRequestParametersValid() {
        when(configurationService.getCredentialIssuer("PassportIssuer")).thenReturn(passportIssuer);

        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                authorization_code,
                                "credential_issuer_id",
                                passportIssuerId),
                        Map.of("ipv-session-id", sessionId));
        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

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
