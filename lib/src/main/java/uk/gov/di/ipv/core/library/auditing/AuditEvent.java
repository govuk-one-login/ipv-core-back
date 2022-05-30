package uk.gov.di.ipv.core.library.auditing;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditEvent {
    @JsonProperty private final int timestamp;

    @JsonProperty("event_name")
    private final AuditEventTypes event;

    @JsonProperty private final AuditExtensionParams extensions;

    @JsonCreator
    public AuditEvent(
            @JsonProperty(value = "timestamp", required = true) int timestamp,
            @JsonProperty(value = "event_name", required = true) AuditEventTypes event,
            @JsonProperty(value = "extensions", required = false) AuditExtensionParams extensions) {
        this.timestamp = timestamp;
        this.event = event;
        this.extensions = extensions;
    }
}
