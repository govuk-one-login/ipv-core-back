package uk.gov.di.ipv.service;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class AccessTokenServiceTest {

    private final AccessTokenService accessTokenService = new AccessTokenService();

    @Test
    public void shouldReturnSuccessfulTokenResponseOnSuccessfulExchange() throws Exception {
        TokenRequest tokenRequest = new TokenRequest(
                null,
                new ClientID("test-client-id"),
                new AuthorizationCodeGrant(
                        new AuthorizationCode("123456"),
                        new URI("http://test.com"))
        );

        TokenResponse response = accessTokenService.exchangeCodeForToken(tokenRequest);

        assertInstanceOf(AccessTokenResponse.class, response);
        assertNotNull(response.toSuccessResponse().getTokens().getAccessToken().getValue());
    }

    @Test
    public void shouldReturnErrorTokenResponseOnNonAuthorisationCodeGrant() throws Exception {
        TokenRequest tokenRequest = new TokenRequest(
                null,
                new ClientID("test-client-id"),
                new RefreshTokenGrant(new RefreshToken())
        );

        TokenResponse response = accessTokenService.exchangeCodeForToken(tokenRequest);

        assertInstanceOf(TokenErrorResponse.class, response);
        assertEquals(response.toErrorResponse().getErrorObject().getCode(), "F-001");
        assertEquals(response.toErrorResponse().getErrorObject().getDescription(), "Something failed during exchange of code to token");
    }
}
