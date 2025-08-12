package uk.gov.di.ipv.core.library.config.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;

@Data
@Builder
@Jacksonized
public class VotCiThresholdsConfig {
    @NonNull
    @JsonProperty("P1")
    final Integer p1;

    @NonNull
    @JsonProperty("P2")
    final Integer p2;

    @NonNull
    @JsonProperty("P3")
    final Integer p3;
}
