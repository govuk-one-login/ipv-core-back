package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditExtensionPreviousIpvSessionId implements AuditExtensions {

    @JsonProperty("previous_ipv_session_id")
    private final String previousIpvSessionId;

    @JsonCreator
    public AuditExtensionPreviousIpvSessionId(
            @JsonProperty(value = "previous_ipv_session_id", required = true)
                    String previousIpvSessionId) {
        this.previousIpvSessionId = previousIpvSessionId;
    }
}
