package uk.gov.di.ipv.core.library.config.domain;

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;

@Data
@Builder
@Jacksonized
public class ClientConfig {
    @NonNull final String id;
    @NonNull final String issuer;
    @NonNull final String publicKeyMaterialForCoreToVerify;
    @NonNull final String validRedirectUrls;
    @NonNull final String validScopes;
    final String jwksUrl; // Null for API test client configs
}
