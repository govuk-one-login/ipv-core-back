package uk.gov.di.ipv.core.builddebugcredentialdata;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class UserIssuedDebugCredential {

    private DebugCredentialAttributes attributes;
    private Map<String, Object> evidence;

    public UserIssuedDebugCredential(DebugCredentialAttributes attributes) {
        this.attributes = attributes;
        this.evidence = null;
    }

    public DebugCredentialAttributes getAttributes() {
        return attributes;
    }

    public void setAttributes(DebugCredentialAttributes attributes) {
        this.attributes = attributes;
    }

    public Map<String, Object> getEvidence() {
        return evidence;
    }

    public void setEvidence(Map<String, Object> evidence) {
        this.evidence = evidence;
    }
}
