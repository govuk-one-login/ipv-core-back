package uk.gov.di.ipv.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import uk.gov.di.ipv.persistence.DataStore;
import uk.gov.di.ipv.persistence.item.AuthorizationCodeItem;

import java.util.Objects;

public class AuthorizationCodeService {
    private final DataStore<AuthorizationCodeItem> dataStore;
    private final ConfigurationService configurationService;

    public AuthorizationCodeService() {
        this.configurationService = ConfigurationService.getInstance();
        this.dataStore = new DataStore<>(configurationService.getAuthCodesTableName(), AuthorizationCodeItem.class);
    }

    public AuthorizationCodeService(DataStore<AuthorizationCodeItem> dataStore, ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dataStore = dataStore;
    }

    public AuthorizationCode generateAuthorizationCode() {
        return new AuthorizationCode();
    }

    public String getIpvSessionIdByAuthorizationCode(String authorizationCode) {
        AuthorizationCodeItem authorizationCodeItem = dataStore.read(authorizationCode);
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
