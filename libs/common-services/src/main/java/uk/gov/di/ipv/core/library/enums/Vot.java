package uk.gov.di.ipv.core.library.enums;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ProfileType;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.helpers.CollectionHelper;

import java.util.List;

import static uk.gov.di.ipv.core.library.domain.ProfileType.GPG45;
import static uk.gov.di.ipv.core.library.domain.ProfileType.OPERATIONAL_HMRC;

@ExcludeFromGeneratedCoverageReport
public enum Vot {
    P0(List.of(), null, GPG45),
    P1(List.of(Gpg45Profile.L1A), null, GPG45),
    P2(
            List.of(Gpg45Profile.M1A, Gpg45Profile.M1B, Gpg45Profile.M2B, Gpg45Profile.M1C),
            null,
            GPG45),
    P3(List.of(Gpg45Profile.H1A), null, GPG45),
    PCL250(null, List.of(OperationalProfile.PCL250), OPERATIONAL_HMRC),
    PCL200(null, List.of(OperationalProfile.PCL250, OperationalProfile.PCL200), OPERATIONAL_HMRC);
    public static final List<Vot> SUPPORTED_VOTS_BY_DESCENDING_STRENGTH =
            List.of(Vot.P3, Vot.P2, Vot.PCL250, Vot.PCL200, Vot.P1);

    private final List<Gpg45Profile> supportedGpg45Profiles;
    private final List<OperationalProfile> supportedOperationalProfiles;
    private final ProfileType profileType;

    Vot(
            List<Gpg45Profile> supportedGpg45Profiles,
            List<OperationalProfile> supportedOperationalProfiles,
            ProfileType profileType) {
        this.supportedGpg45Profiles = supportedGpg45Profiles;
        this.supportedOperationalProfiles = supportedOperationalProfiles;
        this.profileType = profileType;
    }

    public List<Gpg45Profile> getSupportedGpg45Profiles(boolean isFraudScoreRequired) {
        if (isFraudScoreRequired) {
            return supportedGpg45Profiles.stream()
                    .filter(profile -> profile.getScores().getFraud() > 0)
                    .toList();
        }
        return supportedGpg45Profiles;
    }

    public List<OperationalProfile> getSupportedOperationalProfiles() {
        return supportedOperationalProfiles;
    }

    public ProfileType getProfileType() {
        return this.profileType;
    }

    public static Vot fromGpg45Profile(Gpg45Profile profile) {
        return SUPPORTED_VOTS_BY_DESCENDING_STRENGTH.stream()
                .filter(vot -> GPG45.equals(vot.profileType))
                .filter(vot -> vot.getSupportedGpg45Profiles(false).contains(profile))
                .collect(CollectionHelper.toSingleton());
    }
}
