package uk.gov.di.ipv.core.library.domain;

import lombok.Builder;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@Getter
@Builder
@ExcludeFromGeneratedCoverageReport
public class Mitigation {
    private final String mitigationCode;
    private final List<MitigatingCredential> mitigatingCredentials;
}
