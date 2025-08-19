package uk.gov.di.ipv.core.library.config.domain;

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;

import java.util.List;
import java.util.Map;

@Data
@Builder
@Jacksonized
public class CimitConfig {
    @NonNull final String componentId;
    @NonNull final String signingKey;
    @NonNull final Map<String, @NonNull List<@NonNull CiRoutingConfig>> config;
    @NonNull final String apiBaseUrl;
}
