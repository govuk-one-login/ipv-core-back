package uk.gov.di.ipv.core.library.config.domain;

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;

@Data
@Builder
@Jacksonized
public class ClientConfig {
    @NonNull String id;
    @NonNull String issuer;
    @NonNull String publicKeyMaterialForCoreToVerify;
    @NonNull String validRedirectUrls;
    @NonNull String validScopes;
    String jwksUrl; // Null for API test client configs
}
