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
    long jwtTtlSeconds;
    long maxAllowedAuthClientTtl;
    @NonNull Integer fraudCheckExpiryPeriodHours;
    @NonNull Long dcmawAsyncVcPendingReturnTtl;
    @NonNull String clientJarKmsEncryptionKeyAliasPrimary;
    @NonNull String clientJarKmsEncryptionKeyAliasSecondary;
    @NonNull URI coreVtmClaim;
    long backendSessionTimeout;
    long backendSessionTtl;
    long bearerTokenTtl;
    long criResponseTtl;
    long sessionCredentialTtl;
    long authCodeExpirySeconds;
    long oauthKeyCacheDurationMins;
    @NonNull List<ContraIndicatorConfig> ciScoringConfig;
    @NonNull VotCiThresholdsConfig ciScoringThresholdByVot;
    @NonNull Map<String, @NonNull String> returnCodes;
    @NonNull CoiConfig coi;
}
