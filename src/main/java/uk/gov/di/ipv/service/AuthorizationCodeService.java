package uk.gov.di.ipv.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import uk.gov.di.ipv.persistence.DataStore;
import uk.gov.di.ipv.persistence.item.AuthorizationCodeItem;

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

    public void persistAuthorizationCode(String sessionId, String authorizationCode) {
        AuthorizationCodeItem authorizationCodeItem = new AuthorizationCodeItem();
        authorizationCodeItem.setSessionId(sessionId);
        authorizationCodeItem.setCode(authorizationCode);

        dataStore.create(authorizationCodeItem);
    }
}
