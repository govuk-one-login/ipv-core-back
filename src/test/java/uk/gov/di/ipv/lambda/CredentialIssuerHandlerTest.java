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

    @Captor
    private ArgumentCaptor<CredentialIssuerRequestDto> requestDto;

    @Test
    void shouldReceive400ResponseCodeIfAuthorizationCodeNotPresent() throws JsonProcessingException {

        CredentialIssuerHandler handler = new CredentialIssuerHandler();
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();

        input.setBody("credential_issuer_id=foo&redirect_uri=http://www.example.com");
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
        input.setBody("authorization_code=bar&redirect_uri=http://www.example.com");

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

        input.setBody("authorization_code=bar&credential_issuer_id=bar&redirect_uri=http://www.example.com");
        Context context = mock(Context.class);
        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_BAD_REQUEST, statusCode);
        assertEquals(ErrorResponse.InvalidCredentialIssuerId.getCode(), responseBody.get("code"));
        verifyNoInteractions(context);

    }

    @Test
    void shouldReceive400ResponseCodeIfRedirectUriNotPresent() throws JsonProcessingException {

        CredentialIssuerHandler handler = new CredentialIssuerHandler();
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();

        input.setBody("authorization_code=bar&credential_issuer_id=PassportIssuer");
        Context context = mock(Context.class);
        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_BAD_REQUEST, statusCode);
        assertEquals(ErrorResponse.MissingRedirectURI.getCode(), responseBody.get("code"));
        verifyNoInteractions(context);

    }

    @Test
    void shouldReceive200ResponseCodeIfAllRequestParametersValid() {

        String credentialIssuerId = "PassportIssuer";
        String redirectUri = "http://www.example.com";
        String authorization_code = "bar";

        CredentialIssuerConfig passportIssuer = new CredentialIssuerConfig(credentialIssuerId, URI.create(redirectUri));
        CredentialIssuerConfig fraudIssuer = new CredentialIssuerConfig("FraudIssuer", URI.create(redirectUri));
        Set<CredentialIssuerConfig> configs = Set.of(passportIssuer, fraudIssuer);

        CredentialIssuerService credentialIssuerService = mock(CredentialIssuerService.class);
        AccessToken accessToken = mock(AccessToken.class);

        when(credentialIssuerService.exchangeCodeForToken(
                requestDto.capture(),
                ArgumentMatchers.eq(passportIssuer))
        ).thenReturn(accessToken);

        CredentialIssuerHandler handler = new CredentialIssuerHandler(credentialIssuerService, configs);

        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();

        input.setBody(String.format("authorization_code=%s&credential_issuer_id=%s&redirect_uri=%s", authorization_code, credentialIssuerId, redirectUri));
        Context context = mock(Context.class);
        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        Integer statusCode = response.getStatusCode();
        assertEquals(HTTPResponse.SC_OK, statusCode);
        verifyNoInteractions(context);

        CredentialIssuerRequestDto value = requestDto.getValue();

        assertEquals(redirectUri, value.getRedirect_uri());
        assertEquals(credentialIssuerId, value.getCredential_issuer_id());
        assertEquals(authorization_code, value.getAuthorization_code());


    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIsserServiceThrowsException() throws JsonProcessingException {

        String credentialIssuerId = "PassportIssuer";
        String redirectUri = "http://www.example.com";
        String authorization_code = "bar";

        CredentialIssuerConfig passportIssuer = new CredentialIssuerConfig(credentialIssuerId, URI.create(redirectUri));
        CredentialIssuerConfig fraudIssuer = new CredentialIssuerConfig("FraudIssuer", URI.create(redirectUri));
        Set<CredentialIssuerConfig> configs = Set.of(passportIssuer, fraudIssuer);

        CredentialIssuerService credentialIssuerService = mock(CredentialIssuerService.class);

        CredentialIssuerHandler handler = new CredentialIssuerHandler(credentialIssuerService, configs);
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();

        input.setBody(String.format("authorization_code=%s&credential_issuer_id=%s&redirect_uri=%s", authorization_code, credentialIssuerId, redirectUri));
        Context context = mock(Context.class);

        when(credentialIssuerService.exchangeCodeForToken(requestDto.capture(), ArgumentMatchers.eq(passportIssuer)))
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
}
