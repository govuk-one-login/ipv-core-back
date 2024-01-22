package uk.gov.di.ipv.core.library.enums;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
public enum Vot {
    P0(List.of(), null),
    P2(List.of(Gpg45Profile.M1A, Gpg45Profile.M1B, Gpg45Profile.M2B), null),
    PCL250(null, List.of(OperationalProfile.PCL250)),
    PCL200(null, List.of(OperationalProfile.PCL250, OperationalProfile.PCL200));

    private final List<Gpg45Profile> supportedGpg45Profiles;
    private final List<OperationalProfile> supportedOperationalProfiles;

    Vot(
            List<Gpg45Profile> supportedGpg45Profiles,
            List<OperationalProfile> supportedOperationalProfiles) {
        this.supportedGpg45Profiles = supportedGpg45Profiles;
        this.supportedOperationalProfiles = supportedOperationalProfiles;
    }

    public List<Gpg45Profile> getSupportedGpg45Profiles() {
        return supportedGpg45Profiles;
    }

    public List<OperationalProfile> getSupportedOperationalProfiles() {
        return supportedOperationalProfiles;
    }

    public boolean isGpg45() {
        return supportedGpg45Profiles != null;
    }
}
