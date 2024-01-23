package uk.gov.di.ipv.core.library.enums;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ProfileType;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;

import java.util.List;

import static uk.gov.di.ipv.core.library.domain.ProfileType.GPG45;
import static uk.gov.di.ipv.core.library.domain.ProfileType.OPERATIONAL_HMRC;

@ExcludeFromGeneratedCoverageReport
public enum Vot {
    P0(List.of(), null, GPG45),
    P2(List.of(Gpg45Profile.M1A, Gpg45Profile.M1B, Gpg45Profile.M2B), null, GPG45),
    PCL250(null, List.of(OperationalProfile.PCL250), OPERATIONAL_HMRC),
    PCL200(null, List.of(OperationalProfile.PCL250, OperationalProfile.PCL200), OPERATIONAL_HMRC);

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

    public List<Gpg45Profile> getSupportedGpg45Profiles() {
        return supportedGpg45Profiles;
    }

    public List<OperationalProfile> getSupportedOperationalProfiles() {
        return supportedOperationalProfiles;
    }

    public ProfileType getProfileType() {
        return this.profileType;
    }

    public boolean isGpg45() {
        return supportedGpg45Profiles != null;
    }
}
