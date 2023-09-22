package uk.gov.di.ipv.core.library.cimit.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@Getter
@Builder
@ExcludeFromGeneratedCoverageReport
@ToString
public class MitigatingCredential {
    private final String issuer;
    private final String validFrom;
    private final String txn;
    private final String id;
}
