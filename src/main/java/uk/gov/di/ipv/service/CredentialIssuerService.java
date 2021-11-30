package uk.gov.di.ipv.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import uk.gov.di.ipv.domain.CredentialIssuerException;
import uk.gov.di.ipv.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.dto.CredentialIssuerRequestDto;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

public class CredentialIssuerService {

    public AccessToken exchangeCodeForToken(CredentialIssuerRequestDto request, CredentialIssuerConfig config) {

        AuthorizationCode authorizationCode = new AuthorizationCode(request.getAuthorizationCode());
        try {
            TokenRequest tokenRequest = new TokenRequest(
                    config.getTokenUrl(),
                    new ClientID(getClientId()),
                    new AuthorizationCodeGrant(authorizationCode, null)
            );

            HTTPResponse httpResponse = tokenRequest.toHTTPRequest().send();
            TokenResponse tokenResponse = parseTokenResponse(httpResponse);

            if (tokenResponse instanceof TokenErrorResponse) {
                TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
                ErrorObject errorObject = Objects.requireNonNullElse(
                        errorResponse.getErrorObject(),
                        new ErrorObject("unknown", "unknown")
                );
                throw new CredentialIssuerException(String.format("%s: %s", errorObject.getCode(), errorObject.getDescription()));
            }
            return tokenResponse
                    .toSuccessResponse()
                    .getTokens()
                    .getAccessToken();
        } catch (IOException | ParseException e) {
            throw new CredentialIssuerException(e);
        }
    }

    private String getClientId() {
        return Optional.ofNullable(System.getenv("IPV_CLIENT_ID")).orElse("DI IPV CLIENT");
    }

    private TokenResponse parseTokenResponse(HTTPResponse httpResponse) throws ParseException {
        return OIDCTokenResponseParser.parse(httpResponse);
    }

}
