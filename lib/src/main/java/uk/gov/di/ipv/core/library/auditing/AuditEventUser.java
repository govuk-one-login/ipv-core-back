package uk.gov.di.ipv.core.library.auditing;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuditEventUser {

    @JsonProperty(value = "user_id")
    private final String userId;

    @JsonProperty(value = "session_id")
    private final String sessionId;

    public AuditEventUser(String userId, String sessionId) {
        this.userId = userId;
        this.sessionId = sessionId;
    }
}
