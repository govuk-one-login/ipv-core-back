package uk.gov.di.ipv.core.library.config.domain;

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;
import uk.gov.di.ipv.core.library.dto.CriConfig;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.dto.RestCriConfig;

@Data
@Builder
@Jacksonized
public class CredentialIssuersConfig {
    @NonNull CriConnectionWrapper<OauthCriConfig> address;
    @NonNull CriConnectionWrapper<OauthCriConfig> dcmaw;
    @NonNull CriConnectionWrapper<OauthCriConfig> dcmawAsync;
    @NonNull CriConnectionWrapper<OauthCriConfig> fraud;
    @NonNull CriConnectionWrapper<OauthCriConfig> experianKbv;
    @NonNull CriConnectionWrapper<OauthCriConfig> ukPassport;
    @NonNull CriConnectionWrapper<OauthCriConfig> drivingLicence;
    @NonNull CriConnectionWrapper<OauthCriConfig> claimedIdentity;
    @NonNull CriConnectionWrapper<OauthCriConfig> f2f;
    @NonNull CriConnectionWrapper<OauthCriConfig> nino;
    @NonNull CriConnectionWrapper<OauthCriConfig> bav;
    @NonNull CriConnectionWrapper<OauthCriConfig> dwpKbv;
    @NonNull CriConnectionWrapper<RestCriConfig> ticf;

    @SuppressWarnings("unchecked")
    public <T extends CriConfig> CriConnectionWrapper<T> getById(String criId) {
        if (criId == null) {
            return null;
        }
        return (CriConnectionWrapper<T>)
                switch (criId) {
                    case "address" -> address;
                    case "dcmaw" -> dcmaw;
                    case "dcmawAsync" -> dcmawAsync;
                    case "fraud" -> fraud;
                    case "experianKbv" -> experianKbv;
                    case "ukPassport" -> ukPassport;
                    case "drivingLicence" -> drivingLicence;
                    case "claimedIdentity" -> claimedIdentity;
                    case "f2f" -> f2f;
                    case "nino" -> nino;
                    case "bav" -> bav;
                    case "dwpKbv" -> dwpKbv;
                    case "ticf" -> ticf;
                    default -> null;
                };
    }
}
