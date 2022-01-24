package uk.gov.di.ipv.core.library.domain;

public class DebugCredentialAttributes {
    private String ipvSessionId;
    private String dateCreated;

    public DebugCredentialAttributes(String ipvSessionId, String dateCreated) {
        this.ipvSessionId = ipvSessionId;
        this.dateCreated = dateCreated;
    }

    public String getIpvSessionId() {
        return ipvSessionId;
    }

    public void setIpvSessionId(String ipvSessionId) {
        this.ipvSessionId = ipvSessionId;
    }

    public String getDateCreated() {
        return dateCreated;
    }

    public void setDateCreated(String dateCreated) {
        this.dateCreated = dateCreated;
    }
}
