package uk.gov.di.ipv.core.library.domain;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DebugCredentialAttributes {
    private String ipvSessionId;
    private String dateCreated;

    public DebugCredentialAttributes(String ipvSessionId, String dateCreated) {
        this.ipvSessionId = ipvSessionId;
        this.dateCreated = dateCreated;
    }
}
