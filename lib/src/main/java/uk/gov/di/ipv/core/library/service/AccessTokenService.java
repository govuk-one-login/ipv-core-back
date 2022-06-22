package uk.gov.di.ipv.core.library.service;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import org.apache.commons.codec.digest.DigestUtils;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.AccessTokenItem;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

import java.util.Objects;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.ACCESS_TOKENS_TABLE_NAME;

public class AccessTokenService {
    private final DataStore<AccessTokenItem> dataStore;
    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public AccessTokenService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        boolean isRunningLocally = this.configurationService.isRunningLocally();
        this.dataStore =
                new DataStore<>(
                        this.configurationService.getEnvironmentVariable(ACCESS_TOKENS_TABLE_NAME),
                        AccessTokenItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally,
                        configurationService);
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
        AccessTokenItem accessTokenItem = dataStore.getItem(DigestUtils.sha256Hex(accessToken));
        return Objects.isNull(accessTokenItem) ? null : accessTokenItem.getIpvSessionId();
    }

    public void persistAccessToken(AccessTokenResponse tokenResponse, String ipvSessionId) {
        AccessTokenItem accessTokenItem = new AccessTokenItem();
        accessTokenItem.setAccessToken(
                DigestUtils.sha256Hex(tokenResponse.getTokens().getBearerAccessToken().getValue()));
        accessTokenItem.setIpvSessionId(ipvSessionId);
        dataStore.create(accessTokenItem);
    }
}
