package uk.gov.di.ipv.core.library.domain.cimitvc;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@AllArgsConstructor
@NoArgsConstructor(force = true)
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
