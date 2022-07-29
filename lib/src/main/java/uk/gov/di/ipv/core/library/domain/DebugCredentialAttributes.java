package uk.gov.di.ipv.core.library.domain;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DebugCredentialAttributes {
    private String userId;
    private String dateCreated;

    public DebugCredentialAttributes(String ipvSessionId, String dateCreated) {
        this.userId = ipvSessionId;
        this.dateCreated = dateCreated;
    }
}
