package uk.gov.di.ipv.core.library.service;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.DebugCredentialAttributes;
import uk.gov.di.ipv.core.library.domain.UserIssuedDebugCredential;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class UserIdentityService {
    private static final Logger LOGGER = LoggerFactory.getLogger(UserIdentityService.class);
    private static final String GPG45_SCORE_PARAM_NAME = "gpg45Score";

    private final ConfigurationService configurationService;
    private final DataStore<UserIssuedCredentialsItem> dataStore;

    @ExcludeFromGeneratedCoverageReport
    public UserIdentityService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        boolean isRunningLocally = this.configurationService.isRunningLocally();
        this.dataStore =
                new DataStore<>(
                        this.configurationService.getUserIssuedCredentialTableName(),
                        UserIssuedCredentialsItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally);
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

    public Map<String, String> getUserIssuedDebugCredentials(String ipvSessionId) {
        List<UserIssuedCredentialsItem> credentialIssuerItems = dataStore.getItems(ipvSessionId);
        Map<String, String> userIssuedDebugCredentials = new HashMap<>();

        Gson gson = new Gson();
        credentialIssuerItems.forEach(
                criItem -> {
                    DebugCredentialAttributes attributes =
                            new DebugCredentialAttributes(
                                    criItem.getIpvSessionId(), criItem.getDateCreated().toString());
                    UserIssuedDebugCredential debugCredential =
                            new UserIssuedDebugCredential(attributes);

                    Map<String, Object> credentialJson;
                    try {
                        credentialJson = gson.fromJson(criItem.getCredential(), Map.class);

                        if (credentialJson.containsKey(GPG45_SCORE_PARAM_NAME)) {
                            debugCredential.setGpg45Score(
                                    gson.fromJson(
                                            credentialJson.get(GPG45_SCORE_PARAM_NAME).toString(),
                                            Map.class));
                        }
                    } catch (JsonSyntaxException e) {
                        LOGGER.error("Failed to parse credential JSON for the debug page");
                    }

                    String debugCredentialJson = gson.toJson(debugCredential);

                    userIssuedDebugCredentials.put(
                            criItem.getCredentialIssuer(), debugCredentialJson);
                });

        return userIssuedDebugCredentials;
    }
}
