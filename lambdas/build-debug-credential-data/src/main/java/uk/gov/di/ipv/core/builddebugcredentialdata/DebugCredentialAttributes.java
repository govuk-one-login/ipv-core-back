package uk.gov.di.ipv.core.builddebugcredentialdata;

public class DebugCredentialAttributes {
    private String userId;
    private String dateCreated;

    public DebugCredentialAttributes(String ipvSessionId, String dateCreated) {
        this.userId = ipvSessionId;
        this.dateCreated = dateCreated;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getDateCreated() {
        return dateCreated;
    }

    public void setDateCreated(String dateCreated) {
        this.dateCreated = dateCreated;
    }
}
