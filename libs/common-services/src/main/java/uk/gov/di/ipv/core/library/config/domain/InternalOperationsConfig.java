package uk.gov.di.ipv.core.library.config.domain;

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;

import java.util.List;
import java.util.Map;

@Data
@Builder
@Jacksonized
public class InternalOperationsConfig {
    final String configFormat;
    @NonNull final String componentId;
    @NonNull final String signingKeyId;
    @NonNull final String sisSigningKeyId;
    @NonNull final String audienceForClients;
    @NonNull final Integer jwtTtlSeconds;
    @NonNull final Integer maxAllowedAuthClientTtl;
    @NonNull final Integer fraudCheckExpiryPeriodHours;
    @NonNull final Integer dcmawAsyncVcPendingReturnTtl;
    @NonNull final String clientJarKmsEncryptionKeyAliasPrimary;
    @NonNull final String clientJarKmsEncryptionKeyAliasSecondary;
    @NonNull final String coreVtmClaim;
    @NonNull final Integer backendSessionTimeout;
    @NonNull final Integer backendSessionTtl;
    @NonNull final Integer bearerTokenTtl;
    @NonNull final Integer criResponseTtl;
    @NonNull final Integer sessionCredentialTtl;
    @NonNull final Integer authCodeExpirySeconds;
    @NonNull final Integer oauthKeyCacheDurationMins;
    @NonNull final List<ContraIndicatorConfig> ciScoringConfig;
    @NonNull final VotCiThresholdsConfig ciScoringThresholdByVot;
    @NonNull final Map<String, @NonNull String> returnCodes;
    @NonNull final CoiConfig coi;
}
