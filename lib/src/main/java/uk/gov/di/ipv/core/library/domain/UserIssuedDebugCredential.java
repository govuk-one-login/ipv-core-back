package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class UserIssuedDebugCredential {

    DebugCredentialAttributes attributes;
    private Map<String, String> gpg45Score;

    public UserIssuedDebugCredential(DebugCredentialAttributes attributes) {
        this.attributes = attributes;
        this.gpg45Score = null;
    }

    public DebugCredentialAttributes getAttributes() {
        return attributes;
    }

    public void setAttributes(DebugCredentialAttributes attributes) {
        this.attributes = attributes;
    }

    public Map<String, String> getGpg45Score() {
        return gpg45Score;
    }

    public void setGpg45Score(Map<String, String> gpg45Score) {
        this.gpg45Score = gpg45Score;
    }
}
