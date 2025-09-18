package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.net.URI;

@SuperBuilder
@Setter
@Getter
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class RestCriConfig extends CriConfig {
    private static final long DEFAULT_REQUEST_TIMEOUT = 30;

    private Long requestTimeout;
    @NonNull private URI credentialUrl;
    private boolean requiresApiKey;

    public long getRequestTimeout() {
        // This it to avoid having to define the request timeout in config if not desired
        return requestTimeout == null ? DEFAULT_REQUEST_TIMEOUT : requestTimeout;
    }
}
