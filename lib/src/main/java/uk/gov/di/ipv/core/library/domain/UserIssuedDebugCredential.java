package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserIssuedDebugCredential {

    DebugCredentialAttributes attributes;
    private Map<String, Object> evidence;

    public UserIssuedDebugCredential(DebugCredentialAttributes attributes) {
        this.attributes = attributes;
        this.evidence = null;
    }
}
