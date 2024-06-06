package uk.gov.di.ipv.core.library.enums;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum IdentityType {
    @JsonProperty("new")
    NEW,
    @JsonProperty("update")
    UPDATE,
    @JsonProperty("pending")
    PENDING;
}
