package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode
public class ContraIndicatorMitigation {
    @JsonProperty("inter")
    private String interSessionJourney;

    @JsonProperty("intra")
    private String intraSessionJourney;

    @JsonProperty("mit")
    private List<String> mitigatingCredentialIssuers;
}
