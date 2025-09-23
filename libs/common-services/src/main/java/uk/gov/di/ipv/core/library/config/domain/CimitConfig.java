package uk.gov.di.ipv.core.library.config.domain;

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;

import java.net.URI;
import java.util.List;
import java.util.Map;

@Data
@Builder
@Jacksonized
public class CimitConfig {
    @NonNull URI componentId;
    @NonNull String signingKey;
    @NonNull Map<String, @NonNull List<@NonNull CiRoutingConfig>> config;
    @NonNull URI apiBaseUrl;
}
