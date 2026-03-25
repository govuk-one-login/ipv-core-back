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
    String publicKeyMaterialForCoreToVerify; // to be removed once PYIC-8969 is merged
    @NonNull String validRedirectUrls;
    @NonNull String validScopes;
    String jwksUrl; // to be made @NonNull once PYIC-8969 is merged
}
