package uk.gov.di.ipv.core.library.config.domain;

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;

import java.util.Map;

@Data
@Builder
@Jacksonized
public class Config {
    @NonNull final InternalOperationsConfig self;
    @NonNull final Map<String, @NonNull ClientConfig> clients;
    @NonNull final AisConfig ais;
    @NonNull final CimitConfig cimit;
    @NonNull final EvcsConfig evcs;
    @NonNull final StoredIdentityServiceConfig storedIdentityService;
    @NonNull final CredentialIssuersConfig credentialIssuers;
    final Map<String, Map<String, String>> local;
    final Map<String, @NonNull Boolean> featureFlags;
    final Map<String, @NonNull Map<String, ?>> features;

    public ClientConfig getClientConfig(String clientId) {
        return clients.get(clientId);
    }
}
