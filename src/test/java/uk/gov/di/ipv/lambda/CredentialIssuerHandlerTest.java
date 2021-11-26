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
import uk.gov.di.ipv.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.service.CredentialIssuerService;

import java.net.URI;
import java.util.Map;
import java.util.Set;

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

    String credentialIssuerId = "PassportIssuer";
    String redirectUri = "http://www.example.com";
    String authorization_code = "bar";

    @Test
    void shouldReceive400ResponseCodeIfAuthorizationCodeNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = createRequestEvent("credential_issuer_id=foo&redirect_uri=http://www.example.com");
        APIGatewayProxyResponseEvent response = new CredentialIssuerHandler().handleRequest(input, context);
        assert400Response(response, ErrorResponse.MissingAuthorizationCode);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = createRequestEvent("authorization_code=bar&redirect_uri=http://www.example.com");
        APIGatewayProxyResponseEvent response = new CredentialIssuerHandler().handleRequest(input, context);
        assert400Response(response, ErrorResponse.MissingCredentialIssuerId);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotInPermittedSet() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = createRequestEvent("authorization_code=bar&credential_issuer_id=bar&redirect_uri=http://www.example.com");
        APIGatewayProxyResponseEvent response = new CredentialIssuerHandler().handleRequest(input, context);
        assert400Response(response, ErrorResponse.InvalidCredentialIssuerId);
    }

    @Test
    void shouldReceive400ResponseCodeIfRedirectUriNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = createRequestEvent("authorization_code=bar&credential_issuer_id=PassportIssuer");
        APIGatewayProxyResponseEvent response = new CredentialIssuerHandler().handleRequest(input, context);
        assert400Response(response, ErrorResponse.MissingRedirectURI);
    }

    @Test
    void shouldReceive200ResponseCodeIfAllRequestParametersValid() {
        CredentialIssuerConfig passportIssuer = new CredentialIssuerConfig(credentialIssuerId, URI.create(redirectUri));
        CredentialIssuerConfig fraudIssuer = new CredentialIssuerConfig("FraudIssuer", URI.create(redirectUri));
        CredentialIssuerService credentialIssuerService = mock(CredentialIssuerService.class);
        AccessToken accessToken = mock(AccessToken.class);

        when(credentialIssuerService.exchangeCodeForToken(
                requestDto.capture(),
                ArgumentMatchers.eq(passportIssuer))
        ).thenReturn(accessToken);

        CredentialIssuerHandler handler = new CredentialIssuerHandler(credentialIssuerService, Set.of(passportIssuer, fraudIssuer));

        APIGatewayProxyRequestEvent input = createRequestEvent(String.format("authorization_code=%s&credential_issuer_id=%s&redirect_uri=%s", authorization_code, credentialIssuerId, redirectUri));
        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        Integer statusCode = response.getStatusCode();
        assertEquals(HTTPResponse.SC_OK, statusCode);
        CredentialIssuerRequestDto value = requestDto.getValue();
        assertEquals(redirectUri, value.getRedirect_uri());
        assertEquals(credentialIssuerId, value.getCredential_issuer_id());
        assertEquals(authorization_code, value.getAuthorization_code());
        verifyNoInteractions(context);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerServiceThrowsException() throws JsonProcessingException {
        CredentialIssuerConfig passportIssuer = new CredentialIssuerConfig(credentialIssuerId, URI.create(redirectUri));
        CredentialIssuerConfig fraudIssuer = new CredentialIssuerConfig("FraudIssuer", URI.create(redirectUri));
        Set<CredentialIssuerConfig> configs = Set.of(passportIssuer, fraudIssuer);

        CredentialIssuerService credentialIssuerService = mock(CredentialIssuerService.class);

        CredentialIssuerHandler handler = new CredentialIssuerHandler(credentialIssuerService, configs);
        APIGatewayProxyRequestEvent input = createRequestEvent(String.format("authorization_code=%s&credential_issuer_id=%s&redirect_uri=%s", authorization_code, credentialIssuerId, redirectUri));

        when(credentialIssuerService.exchangeCodeForToken(requestDto.capture(), ArgumentMatchers.eq(passportIssuer)))
                .thenThrow(new CredentialIssuerException("code1: message1"));

        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        assert400Response(response, ErrorResponse.InvalidTokenRequest);
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

    private void assert400Response(APIGatewayProxyResponseEvent response, ErrorResponse missingAuthorizationCode) throws JsonProcessingException {
        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_BAD_REQUEST, statusCode);
        assertEquals(missingAuthorizationCode.getCode(), responseBody.get("code"));
        verifyNoInteractions(context);
    }
}
