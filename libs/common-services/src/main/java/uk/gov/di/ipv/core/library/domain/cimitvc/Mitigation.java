package uk.gov.di.ipv.core.library.domain.cimitvc;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor(force = true)
@Getter
@Builder
@ExcludeFromGeneratedCoverageReport
@ToString
public class Mitigation {
    private final String code;
    private final List<MitigatingCredential> mitigatingCredential;
}
