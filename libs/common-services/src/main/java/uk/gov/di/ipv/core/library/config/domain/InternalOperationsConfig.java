package uk.gov.di.ipv.core.library.config.domain;

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Data
@Builder
@Jacksonized
public class InternalOperationsConfig {
    String configFormat;
    @NonNull URI componentId;
    @NonNull UUID signingKeyId;
    @NonNull UUID sisSigningKeyId;
    @NonNull URI audienceForClients;
    @NonNull Integer jwtTtlSeconds;
    @NonNull Integer maxAllowedAuthClientTtl;
    @NonNull Integer fraudCheckExpiryPeriodHours;
    @NonNull Integer dcmawAsyncVcPendingReturnTtl;
    @NonNull String clientJarKmsEncryptionKeyAliasPrimary;
    @NonNull String clientJarKmsEncryptionKeyAliasSecondary;
    @NonNull URI coreVtmClaim;
    @NonNull Integer backendSessionTimeout;
    @NonNull Integer backendSessionTtl;
    @NonNull Integer bearerTokenTtl;
    @NonNull Integer criResponseTtl;
    @NonNull Integer sessionCredentialTtl;
    @NonNull Integer authCodeExpirySeconds;
    @NonNull Integer oauthKeyCacheDurationMins;
    @NonNull List<ContraIndicatorConfig> ciScoringConfig;
    @NonNull VotCiThresholdsConfig ciScoringThresholdByVot;
    @NonNull Map<String, @NonNull String> returnCodes;
    @NonNull CoiConfig coi;
}
