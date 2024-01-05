package uk.gov.di.ipv.core.library.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.net.URI;

@SuperBuilder
@Getter
@NoArgsConstructor
public class RestCriConfig extends CriConfig {
    private boolean requiresApiKey;

    public RestCriConfig(
            URI credentialUrl, String signingKey, String componentId, boolean requiresApiKey) {
        super(credentialUrl, signingKey, componentId);
        this.requiresApiKey = requiresApiKey;
    }
}
