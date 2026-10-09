package uk.gov.di.ipv.core.library.config.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;
import uk.gov.di.ipv.core.library.enums.Vot;

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

    public int getThreshold(Vot vot) {
        return switch (vot) {
            case Vot.P1 -> p1;
            case Vot.P2 -> p2;
            case Vot.P3 -> p3;
            default -> throw new IllegalArgumentException("Invalid vot type");
        };
    }
}
