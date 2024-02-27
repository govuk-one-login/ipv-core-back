package uk.gov.di.ipv.core.library.domain.cimitvc;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@Getter
@Builder
@ExcludeFromGeneratedCoverageReport
@ToString
@EqualsAndHashCode
public class Mitigation {
    private final String code;
    private final List<MitigatingCredential> mitigatingCredential;

    public Mitigation(
            @JsonProperty("code") String code,
            @JsonProperty("mitigatingCredential") List<MitigatingCredential> mitigatingCredential) {
        this.code = code;
        this.mitigatingCredential = mitigatingCredential;
    }
}
