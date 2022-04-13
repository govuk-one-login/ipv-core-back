package uk.gov.di.ipv.core.library.auditing;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditEvent {
    @JsonProperty private long timestamp;

    @JsonProperty("event_name")
    private String eventName;

    @JsonCreator
    public AuditEvent(
            @JsonProperty(value = "timestamp", required = true) long timestamp,
            @JsonProperty(value = "event_name", required = true) String eventName) {
        this.timestamp = timestamp;
        this.eventName = eventName;
    }
}
