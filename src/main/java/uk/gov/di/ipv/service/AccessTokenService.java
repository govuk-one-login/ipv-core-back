package uk.gov.di.ipv.service;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import uk.gov.di.ipv.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.persistence.DataStore;
import uk.gov.di.ipv.persistence.item.AccessTokenItem;
import uk.gov.di.ipv.validation.ValidationResult;

import java.util.Objects;

public class AccessTokenService {
    private final DataStore<AccessTokenItem> dataStore;
    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public AccessTokenService() {
        this.configurationService = new ConfigurationService();
        this.dataStore =
                new DataStore<>(
                        configurationService.getAccessTokensTableName(),
                        AccessTokenItem.class,
                        DataStore.getClient());
    }

    public AccessTokenService(
            DataStore<AccessTokenItem> dataStore, ConfigurationService configurationService) {
        this.dataStore = dataStore;
        this.configurationService = configurationService;
    }

    public TokenResponse generateAccessToken(TokenRequest tokenRequest) {
        AccessToken accessToken =
                new BearerAccessToken(
                        configurationService.getBearerAccessTokenTtl(), tokenRequest.getScope());
        return new AccessTokenResponse(new Tokens(accessToken, null));
    }

    public ValidationResult<ErrorObject> validateTokenRequest(TokenRequest tokenRequest) {
        if (!tokenRequest.getAuthorizationGrant().getType().equals(GrantType.AUTHORIZATION_CODE)) {
            return new ValidationResult<>(false, OAuth2Error.UNSUPPORTED_GRANT_TYPE);
        }
        return ValidationResult.createValidResult();
    }

    public String getIpvSessionIdByAccessToken(String accessToken) {
        AccessTokenItem accessTokenItem = dataStore.getItem(accessToken);
        return Objects.isNull(accessTokenItem) ? null : accessTokenItem.getIpvSessionId();
    }

    public void persistAccessToken(AccessTokenResponse tokenResponse, String ipvSessionId) {
        AccessTokenItem accessTokenItem = new AccessTokenItem();
        accessTokenItem.setAccessToken(
                tokenResponse.getTokens().getBearerAccessToken().toAuthorizationHeader());
        accessTokenItem.setIpvSessionId(ipvSessionId);
        dataStore.create(accessTokenItem);
    }
}
