package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AuditExtensionReverification(
        @JsonProperty("success") boolean success, @JsonProperty("failure_code") String failureCode)
        implements AuditExtensions {}
