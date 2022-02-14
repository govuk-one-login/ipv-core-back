package uk.gov.di.ipv.core.library.service;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.AccessTokenItem;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

import java.text.ParseException;
import java.util.Map;
import java.util.Objects;

public class AccessTokenService {
    private final DataStore<AccessTokenItem> dataStore;
    private final ConfigurationService configurationService;

    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenService.class);

    @ExcludeFromGeneratedCoverageReport
    public AccessTokenService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        boolean isRunningLocally = this.configurationService.isRunningLocally();
        this.dataStore =
                new DataStore<>(
                        this.configurationService.getAccessTokensTableName(),
                        AccessTokenItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally);
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

    public ValidationResult<ErrorObject> extractJwt(String requestBody) {

        Map<String, String> stringMap = RequestHelper.parseRequestBody(requestBody);

        try {
            SignedJWT str = SignedJWT.parse(String.valueOf(stringMap.get("client_assertion")));

            JWTClaimsSet claimsSet = str.getJWTClaimsSet();

            if (claimsSet != null) {
                return ValidationResult.createValidResult();
            }
        } catch (ParseException e) {
            LOGGER.error("Unable to parse Claims set {} ", e.getMessage());
            return new ValidationResult<>(false, OAuth2Error.INVALID_REQUEST_OBJECT);
        }
        return ValidationResult.createValidResult();
    }
}
