package uk.gov.di.ipv.core.builddebugcredentialdata;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
@NoArgsConstructor
@AllArgsConstructor
@Data
public class UserIssuedDebugCredential {

    private DebugCredentialAttributes attributes;
    private Map<String, Object> evidence;

    public UserIssuedDebugCredential(DebugCredentialAttributes attributes) {
        this.attributes = attributes;
    }
}
