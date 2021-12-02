package uk.gov.di.ipv.service;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.client.ClientReadRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.domain.CredentialIssuerException;
import uk.gov.di.ipv.domain.ErrorResponse;
import uk.gov.di.ipv.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.persistence.DataStore;
import uk.gov.di.ipv.persistence.item.UserIssuedCredentialsItem;

import java.io.IOException;
import java.net.URI;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.Optional;

public class CredentialIssuerService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CredentialIssuerService.class);

    private final DataStore<UserIssuedCredentialsItem> dataStore;
    private final ConfigurationService configurationService;

    public CredentialIssuerService() {
        this.configurationService = ConfigurationService.getInstance();
        this.dataStore = new DataStore<>(configurationService.getUserIssuedCredentialTableName(), UserIssuedCredentialsItem.class);
    }

    // used for testing
    public CredentialIssuerService(DataStore<UserIssuedCredentialsItem> dataStore, ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dataStore = dataStore;
    }

    public BearerAccessToken exchangeCodeForToken(CredentialIssuerRequestDto request, CredentialIssuerConfig config) {

        AuthorizationCode authorizationCode = new AuthorizationCode(request.getAuthorizationCode());
        try {
            TokenRequest tokenRequest = new TokenRequest(
                    config.getTokenUrl(),
                    new ClientID(getClientId()),
                    new AuthorizationCodeGrant(authorizationCode, URI.create(request.getRedirectUri()))
            );

            HTTPResponse httpResponse = tokenRequest.toHTTPRequest().send();
            TokenResponse tokenResponse = parseTokenResponse(httpResponse);

            if (tokenResponse instanceof TokenErrorResponse) {
                TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
                ErrorObject errorObject = Objects.requireNonNullElse(
                        errorResponse.getErrorObject(),
                        new ErrorObject("unknown", "unknown")
                );
                LOGGER.error("{}: {}", errorObject.getCode(), errorObject.getDescription());
                throw new CredentialIssuerException(HTTPResponse.SC_BAD_REQUEST, ErrorResponse.INVALID_TOKEN_REQUEST);
            }
            return tokenResponse
                    .toSuccessResponse()
                    .getTokens()
                    .getBearerAccessToken();
        } catch (IOException | ParseException e) {
            LOGGER.error("Error exchanging token: {}", e.getMessage(), e);
            throw new CredentialIssuerException(HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE);
        }
    }

    public JSONObject getCredential(BearerAccessToken accessToken, CredentialIssuerConfig config) {
        ClientReadRequest credentialRequest = new ClientReadRequest(
                config.getCredentialUrl(),
                accessToken
        );

        try {
            HTTPResponse response = credentialRequest.toHTTPRequest().send();
            if (!response.indicatesSuccess()) {
                LOGGER.error("Error retrieving credential: {} - {}", response.getStatusCode(), response.getStatusMessage());
                throw new CredentialIssuerException(
                        HTTPResponse.SC_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER
                );
            }

            return response.getContentAsJSONObject(); // In future we can use response.getContentAsJWT()
        } catch (IOException | ParseException e) {
            LOGGER.error("Error retrieving credential: {}", e.getMessage(), e);
            throw new CredentialIssuerException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER
            );
        }
    }

    private String getClientId() {
        return Optional.ofNullable(System.getenv("IPV_CLIENT_ID")).orElse("DI IPV CLIENT");
    }

    private TokenResponse parseTokenResponse(HTTPResponse httpResponse) throws ParseException {
        return OIDCTokenResponseParser.parse(httpResponse);
    }

    public void persistUserCredentials(JSONObject credential, CredentialIssuerRequestDto request) {
        UserIssuedCredentialsItem userIssuedCredentials = new UserIssuedCredentialsItem();
        userIssuedCredentials.setIpvSessionId(request.getIpvSessionId());
        userIssuedCredentials.setCredentialIssuer(request.getCredentialIssuerId());
        userIssuedCredentials.setCredential(credential.toJSONString());
        userIssuedCredentials.setDateCreated(LocalDateTime.now());
        try {
            dataStore.create(userIssuedCredentials);
        } catch (UnsupportedOperationException e) {
            LOGGER.error("Error persisting user credential: {}", e.getMessage(), e);
            throw new CredentialIssuerException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_SAVE_CREDENTIAL
            );
        }
    }
}
