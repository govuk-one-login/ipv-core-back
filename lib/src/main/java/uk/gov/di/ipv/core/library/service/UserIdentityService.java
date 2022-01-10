package uk.gov.di.ipv.core.library.service;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class UserIdentityService {
    private final ConfigurationService configurationService;
    private final DataStore<UserIssuedCredentialsItem> dataStore;

    @ExcludeFromGeneratedCoverageReport
    public UserIdentityService() {
        this.configurationService = new ConfigurationService();
        this.dataStore =
                new DataStore<>(
                        configurationService.getUserIssuedCredentialTableName(),
                        UserIssuedCredentialsItem.class,
                        DataStore.getClient());
    }

    public UserIdentityService(
            ConfigurationService configurationService,
            DataStore<UserIssuedCredentialsItem> dataStore) {
        this.configurationService = configurationService;
        this.dataStore = dataStore;
    }

    public Map<String, String> getUserIssuedCredentials(String ipvSessionId) {
        List<UserIssuedCredentialsItem> credentialIssuerItem = dataStore.getItems(ipvSessionId);

        return credentialIssuerItem.stream()
                .map(ciItem -> Map.entry(ciItem.getCredentialIssuer(), ciItem.getCredential()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }
}
