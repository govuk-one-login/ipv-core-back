package uk.gov.di.ipv.core.library.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.net.URI;

@SuperBuilder
@Getter
@NoArgsConstructor
public class RestCriConfig extends CriConfig {
    private URI credentialUrl;
    private boolean requiresApiKey;

    public RestCriConfig(
            URI credentialUrl, String signingKey, String componentId, boolean requiresApiKey) {
        super(signingKey, componentId);
        this.credentialUrl = credentialUrl;
        this.requiresApiKey = requiresApiKey;
    }
}
