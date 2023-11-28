package uk.gov.di.ipv.core.library.dto;

import com.nimbusds.jose.jwk.ECKey;
import lombok.Getter;

import java.net.URI;
import java.text.ParseException;

@Getter
public class BackEndCriConfig implements CriConfig {

    private URI credentialUrl;
    private String signingKey;
    private String componentId;
    private boolean requiresApiKey;

    public BackEndCriConfig() {}

    public BackEndCriConfig(
            URI credentialUrl, String signingKey, String componentId, boolean requiresApiKey) {
        this.credentialUrl = credentialUrl;
        this.signingKey = signingKey;
        this.componentId = componentId;
        this.requiresApiKey = requiresApiKey;
    }

    public ECKey getSigningKey() throws ParseException {
        return ECKey.parse(signingKey);
    }

    public boolean requiresApiKey() {
        return requiresApiKey;
    }
}
