package uk.gov.di.ipv.core.library.dto;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.net.URI;

@SuperBuilder
@Getter
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class RestCriConfig extends CriConfig {
    private URI credentialUrl;
    private boolean requiresApiKey;
}
