package uk.gov.di.ipv.core.library.ais.enums;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum AisAuditLevel {
    @JsonProperty("standard") STANDARD,
    @JsonProperty("enhanced") ENHANCED
}
