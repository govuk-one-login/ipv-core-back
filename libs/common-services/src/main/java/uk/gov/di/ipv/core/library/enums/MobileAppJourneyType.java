package uk.gov.di.ipv.core.library.enums;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum MobileAppJourneyType {
    @JsonProperty("mam")
    MAM,
    @JsonProperty("dad")
    DAD,
}
