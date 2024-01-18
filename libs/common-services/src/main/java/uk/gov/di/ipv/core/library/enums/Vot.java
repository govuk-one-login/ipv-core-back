package uk.gov.di.ipv.core.library.enums;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
public enum Vot {
    P0(List.of(), List.of()),
    P2(List.of(Gpg45Profile.M1A, Gpg45Profile.M1B, Gpg45Profile.M2B), List.of()),
    PCL250(List.of(), List.of(OperationalProfile.PCL250)),
    PCL200(List.of(), List.of(OperationalProfile.PCL250, OperationalProfile.PCL200));

    private final List<Gpg45Profile> validGpg45Profiles;
    private final List<OperationalProfile> validOperationalProfiles;

    Vot(List<Gpg45Profile> validGpg45Profiles, List<OperationalProfile> validOperationalProfiles) {
        this.validGpg45Profiles = validGpg45Profiles;
        this.validOperationalProfiles = validOperationalProfiles;
    }

    public List<Gpg45Profile> getValidGpg45Profiles() {
        return validGpg45Profiles;
    }

    public List<OperationalProfile> getValidOperationalProfiles() {
        return validOperationalProfiles;
    }

    public boolean hasGpg45Profiles() {
        return validGpg45Profiles != null && !validGpg45Profiles.isEmpty();
    }
}
