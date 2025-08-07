package uk.gov.di.ipv.core.library.config.domain;

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.dto.RestCriConfig;

@Data
@Builder
@Jacksonized
public class CredentialIssuersConfig {
    @NonNull final CriConnectionWrapper<OauthCriConfig> address;
    @NonNull final CriConnectionWrapper<OauthCriConfig> dcmaw;
    @NonNull final CriConnectionWrapper<OauthCriConfig> dcmawAsync;
    @NonNull final CriConnectionWrapper<OauthCriConfig> fraud;
    @NonNull final CriConnectionWrapper<OauthCriConfig> experianKbv;
    @NonNull final CriConnectionWrapper<OauthCriConfig> ukPassport;
    @NonNull final CriConnectionWrapper<OauthCriConfig> drivingLicence;
    @NonNull final CriConnectionWrapper<OauthCriConfig> claimedIdentity;
    @NonNull final CriConnectionWrapper<OauthCriConfig> f2f;
    @NonNull final CriConnectionWrapper<OauthCriConfig> nino;
    @NonNull final CriConnectionWrapper<OauthCriConfig> bav;
    @NonNull final CriConnectionWrapper<OauthCriConfig> dwpKbv;
    @NonNull final CriConnectionWrapper<RestCriConfig> ticf;
}
