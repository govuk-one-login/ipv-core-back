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
    @NonNull InternalOperationsConfig self;
    @NonNull Map<String, @NonNull ClientConfig> clients;
    @NonNull AisConfig ais;
    @NonNull CimitConfig cimit;
    @NonNull EvcsConfig evcs;
    SisConfig sis;
    @NonNull StoredIdentityServiceConfig storedIdentityService;
    @NonNull CredentialIssuersConfig credentialIssuers;
    Map<String, Map<String, String>> local;
    Map<String, @NonNull Boolean> featureFlags;
    Map<String, @NonNull Map<String, ?>> features;

    public ClientConfig getClientConfig(String clientId) {
        return clients.get(clientId);
    }
}
