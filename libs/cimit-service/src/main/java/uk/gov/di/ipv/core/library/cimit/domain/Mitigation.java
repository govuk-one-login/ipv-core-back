package uk.gov.di.ipv.core.library.cimit.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@Getter
@Builder
@ExcludeFromGeneratedCoverageReport
@ToString
public class Mitigation {
    private final String code;
    private final List<MitigatingCredential> mitigatingCredential;
}
