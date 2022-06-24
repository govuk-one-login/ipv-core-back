package uk.gov.di.ipv.core.library.auditing;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditEventUser {

    @JsonProperty(value = "user_id")
    private final String userId;

    @JsonProperty(value = "session_id")
    private final String sessionId;

    public AuditEventUser(
            @JsonProperty(value = "user_id", required = false) String userId,
            @JsonProperty(value = "session_id", required = false) String sessionId) {
        this.userId = userId;
        this.sessionId = sessionId;
    }
}
