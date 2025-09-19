package uk.gov.di.ipv.core.library.config.domain;

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;

import java.net.URI;

@Data
@Builder
@Jacksonized
public class EvcsConfig {
    @NonNull URI applicationUrl;
}
