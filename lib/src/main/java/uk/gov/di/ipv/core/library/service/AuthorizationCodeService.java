package uk.gov.di.ipv.core.library.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.apache.commons.codec.digest.DigestUtils;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.AuthorizationCodeItem;

import java.time.Instant;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.AUTH_CODES_TABLE_NAME;

public class AuthorizationCodeService {
    private final DataStore<AuthorizationCodeItem> dataStore;
    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public AuthorizationCodeService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        boolean isRunningLocally = this.configurationService.isRunningLocally();
        this.dataStore =
                new DataStore<>(
                        this.configurationService.getEnvironmentVariable(AUTH_CODES_TABLE_NAME),
                        AuthorizationCodeItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally,
                        configurationService);
    }

    public AuthorizationCodeService(
            DataStore<AuthorizationCodeItem> dataStore, ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dataStore = dataStore;
    }

    public AuthorizationCode generateAuthorizationCode() {
        return new AuthorizationCode();
    }

    public Optional<AuthorizationCodeItem> getAuthorizationCodeItem(String authorizationCode) {
        AuthorizationCodeItem authorizationCodeItem =
                dataStore.getItem(DigestUtils.sha256Hex(authorizationCode));
        return Optional.ofNullable(authorizationCodeItem);
    }

    public void persistAuthorizationCode(
            String authorizationCode, String ipvSessionId, String redirectUrl) {
        AuthorizationCodeItem authorizationCodeItem = new AuthorizationCodeItem();
        authorizationCodeItem.setAuthCode(DigestUtils.sha256Hex(authorizationCode));
        authorizationCodeItem.setIpvSessionId(ipvSessionId);
        authorizationCodeItem.setRedirectUrl(redirectUrl);

        dataStore.create(authorizationCodeItem);
    }

    public void setIssuedAccessToken(String authorizationCode, String accessToken) {
        AuthorizationCodeItem authorizationCodeItem = dataStore.getItem(authorizationCode);
        authorizationCodeItem.setIssuedAccessToken(DigestUtils.sha256Hex(accessToken));
        authorizationCodeItem.setExchangeDateTime(Instant.now().toString());

        dataStore.update(authorizationCodeItem);
    }
}
