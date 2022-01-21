package uk.gov.di.ipv.core.library.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.AuthorizationCodeItem;

import java.util.Objects;

public class AuthorizationCodeService {
    private final DataStore<AuthorizationCodeItem> dataStore;
    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public AuthorizationCodeService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dataStore =
                new DataStore<>(
                        this.configurationService.getAuthCodesTableName(),
                        AuthorizationCodeItem.class,
                        DataStore.getClient(),
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

    public String getIpvSessionIdByAuthorizationCode(String authorizationCode) {
        AuthorizationCodeItem authorizationCodeItem = dataStore.getItem(authorizationCode);
        return Objects.isNull(authorizationCodeItem)
                ? null
                : authorizationCodeItem.getIpvSessionId();
    }

    public void persistAuthorizationCode(String authorizationCode, String ipvSessionId) {
        AuthorizationCodeItem authorizationCodeItem = new AuthorizationCodeItem();
        authorizationCodeItem.setAuthCode(authorizationCode);
        authorizationCodeItem.setIpvSessionId(ipvSessionId);

        dataStore.create(authorizationCodeItem);
    }

    public void revokeAuthorizationCode(String authorizationCode) {
        dataStore.delete(authorizationCode);
    }
}
