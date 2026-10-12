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
    Integer p1;

    @NonNull
    @JsonProperty("P2")
    Integer p2;

    @NonNull
    @JsonProperty("P3")
    Integer p3;

    public Integer getThreshold(String vot) {
        return switch (vot.toUpperCase()) {
            case "P1" -> p1;
            case "P2" -> p2;
            case "P3" -> p3;
            default -> null;
        };
    }
}
