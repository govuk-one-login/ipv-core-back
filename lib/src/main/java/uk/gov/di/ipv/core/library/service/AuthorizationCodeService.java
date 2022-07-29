package uk.gov.di.ipv.core.library.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.dto.AuthorizationCodeMetadata;

import java.time.Instant;

public class AuthorizationCodeService {
    private final ConfigurationService configurationService;

    public AuthorizationCodeService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public AuthorizationCode generateAuthorizationCode() {
        return new AuthorizationCode();
    }

    public boolean isExpired(AuthorizationCodeMetadata authorizationCodeMetadata) {
        return Instant.parse(authorizationCodeMetadata.getCreationDateTime())
                .isBefore(
                        Instant.now()
                                .minusSeconds(
                                        Long.parseLong(
                                                configurationService.getSsmParameter(
                                                        ConfigurationVariable
                                                                .AUTH_CODE_EXPIRY_SECONDS))));
    }
}
