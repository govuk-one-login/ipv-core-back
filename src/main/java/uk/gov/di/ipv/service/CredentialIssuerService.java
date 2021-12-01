package uk.gov.di.ipv.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.client.ClientReadRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import net.minidev.json.JSONObject;
import uk.gov.di.ipv.domain.CredentialIssuerException;
import uk.gov.di.ipv.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.persistence.DataStore;
import uk.gov.di.ipv.persistence.item.UserIssuedCredentialsItem;

import java.io.IOException;
import java.time.LocalDate;
import java.util.Objects;
import java.util.Optional;

public class CredentialIssuerService {

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
                    .getBearerAccessToken();
        } catch (IOException | ParseException e) {
            throw new CredentialIssuerException(e);
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
                throw new CredentialIssuerException(
                        String.format("%s: %s", response.getStatusCode(), response.getStatusMessage())
                );
            }

            return response.getContentAsJSONObject(); // In future we can use response.getContentAsJWT()
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

    public void persistUserCredentials(JSONObject credential, CredentialIssuerRequestDto request) {
        UserIssuedCredentialsItem userIssuedCredentials = new UserIssuedCredentialsItem();
        userIssuedCredentials.setSessionId(request.getIpvSessionId());
        userIssuedCredentials.setCredentialIssuer(request.getCredentialIssuerId());
        userIssuedCredentials.setCredential(credential.toJSONString());
        // TODO store json - credentialData
        userIssuedCredentials.setDateCreated(LocalDate.now());
        try {
            dataStore.create(userIssuedCredentials);
        } catch (UnsupportedOperationException e) {
            throw new CredentialIssuerException(e);
        }
    }
}
