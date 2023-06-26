package uk.gov.di.ipv.core.library.domain;

import lombok.Builder;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.time.Instant;

@Getter
@Builder
@ExcludeFromGeneratedCoverageReport
public class MitigatingCredential {
    private final String issuer;
    private final Instant validFrom;
    private final String transactionId;
    private final String userId;
}
