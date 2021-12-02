package uk.gov.di.ipv.service;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;

public class AccessTokenService {

    public TokenResponse exchangeCodeForToken(TokenRequest tokenRequest) {
        if (!tokenRequest.getAuthorizationGrant().getType().equals(GrantType.AUTHORIZATION_CODE)) {
            return new TokenErrorResponse(
                    new ErrorObject("F-001", "Something failed during exchange of code to token"));
        }

        AccessToken accessToken = new BearerAccessToken();

        return new AccessTokenResponse(new Tokens(accessToken, null));
    }
}
