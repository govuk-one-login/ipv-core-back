package uk.gov.di.ipv.domain.gpg45;

import com.fasterxml.jackson.annotation.JsonEnumDefaultValue;

public enum IdentityProfileIdentifier {

    @JsonEnumDefaultValue
    NA,

    L1A, L1B, L1C, L2A, L2B, L3A,

    M1A, M1B, M1C, M1D, M2A, M2B, M2C, M3A,

    H1A, H1B, H1C, H2A, H2B, H2C, H2D, H2E, H3A,

    V1A, V1B, V1C, V1D, V2A, V2B, V2C, V2D, V3A;
}
