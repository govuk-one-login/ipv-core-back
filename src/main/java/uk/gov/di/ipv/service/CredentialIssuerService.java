package uk.gov.di.ipv.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.domain.CredentialIssuerException;
import uk.gov.di.ipv.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.dto.CredentialIssuerRequestDto;

import javax.security.auth.login.CredentialException;
import java.io.IOException;
import java.net.URI;

public class CredentialIssuerService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CredentialIssuerService.class);

    public AccessToken exchangeCodeForToken(CredentialIssuerRequestDto request, CredentialIssuerConfig config) {

        AuthorizationCode authorizationCode = new AuthorizationCode(request.getAuthorization_code());

        try {
            TokenRequest tokenRequest = new TokenRequest(
                    config.getTokenUrl(),
                    new ClientID("IPV_CLIENT_1"),
                    new AuthorizationCodeGrant(authorizationCode, URI.create(request.getRedirect_uri()))
            );

            HTTPResponse httpResponse = tokenRequest.toHTTPRequest().send();
            TokenResponse tokenResponse = parseTokenResponse(httpResponse);

            if (tokenResponse instanceof TokenErrorResponse) {
                TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
                var description = errorResponse.getErrorObject().getDescription();
                var code = errorResponse.getErrorObject().getCode();
                // todo handle logging
                throw new CredentialIssuerException(code + " " + description); //todo handle what exception if any to return

            }
            return tokenResponse
                    .toSuccessResponse()
                    .getTokens()
                    .getAccessToken();
        } catch (IOException | ParseException e) {
            throw new CredentialIssuerException(e); //todo fixme
        }

    }

    private TokenResponse parseTokenResponse(HTTPResponse httpResponse) throws ParseException {
        return OIDCTokenResponseParser.parse(httpResponse);

    }

    private HTTPResponse sendHttpRequest(HTTPRequest httpRequest) {
        try {
            return httpRequest.send();
        } catch (IOException | SerializeException exception) {
            LOGGER.error("Failed to send a http request", exception);
            // todo what error to throw, and how to handle
            throw new RuntimeException("Failed to send a http request", exception);
        }
    }

}
