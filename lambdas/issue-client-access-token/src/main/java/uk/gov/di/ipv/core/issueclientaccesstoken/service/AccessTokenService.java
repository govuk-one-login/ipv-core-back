package uk.gov.di.ipv.core.issueclientaccesstoken.service;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

public class AccessTokenService {
    protected static final Scope DEFAULT_SCOPE = new Scope("user-credentials");
    private final ConfigService configService;

    public AccessTokenService(ConfigService configService) {
        this.configService = configService;
    }

    public TokenResponse generateAccessToken() {
        AccessToken accessToken =
                new BearerAccessToken(configService.getBearerAccessTokenTtl(), DEFAULT_SCOPE);
        return new AccessTokenResponse(new Tokens(accessToken, null));
    }

    public ValidationResult<ErrorObject> validateAuthorizationGrant(AuthorizationGrant authGrant) {
        if (!authGrant.getType().equals(GrantType.AUTHORIZATION_CODE)) {
            return new ValidationResult<>(false, OAuth2Error.UNSUPPORTED_GRANT_TYPE);
        }
        return ValidationResult.createValidResult();
    }
}
