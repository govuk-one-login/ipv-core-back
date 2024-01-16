package uk.gov.di.ipv.core.library.domain;

import static uk.gov.di.ipv.core.library.domain.ProfileType.GPG45;
import static uk.gov.di.ipv.core.library.domain.ProfileType.OPERATIONAL;

public enum VectorOfTrust {
    P0(GPG45),
    P2(GPG45),
    PCL200(OPERATIONAL),
    PCL250(OPERATIONAL);

    private final ProfileType profileType;

    public ProfileType getProfileType() {
        return this.profileType;
    }

    VectorOfTrust(ProfileType profileType) {
        this.profileType = profileType;
    }
}
