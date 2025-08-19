package uk.gov.di.ipv.core.library.enums;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.helpers.CollectionHelper;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
public enum Vot {
    P0(List.of()),
    P1(List.of(Gpg45Profile.L1A)),
    P2(List.of(Gpg45Profile.M1A, Gpg45Profile.M1B, Gpg45Profile.M2B, Gpg45Profile.M1C)),
    P3(List.of(Gpg45Profile.H1A));
    public static final List<Vot> SUPPORTED_VOTS_BY_DESCENDING_STRENGTH =
            List.of(Vot.P3, Vot.P2, Vot.P1);

    private final List<Gpg45Profile> supportedGpg45Profiles;

    Vot(List<Gpg45Profile> supportedGpg45Profiles) {
        this.supportedGpg45Profiles = supportedGpg45Profiles;
    }

    public List<Gpg45Profile> getSupportedGpg45Profiles(boolean isFraudScoreRequired) {
        if (isFraudScoreRequired) {
            return supportedGpg45Profiles.stream()
                    .filter(profile -> profile.getScores().getFraud() > 0)
                    .toList();
        }
        return supportedGpg45Profiles;
    }

    public static Vot fromGpg45Profile(Gpg45Profile profile) {
        return SUPPORTED_VOTS_BY_DESCENDING_STRENGTH.stream()
                .filter(vot -> vot.getSupportedGpg45Profiles(false).contains(profile))
                .collect(CollectionHelper.toSingleton());
    }
}
