package uk.gov.di.ipv.core.library.sis.audit;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestricted;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditRestrictedSisComparison implements AuditRestricted {

    private final String sisJwt;
    private final List<String> reconstructedSignatures;
    private final List<String> sisSignatures;
    private final String failureDetails;

    public AuditRestrictedSisComparison(
            String sisJwt,
            List<String> reconstructedSignatures,
            List<String> sisSignatures,
            String failureDetails) {
        this.sisJwt = sisJwt;
        this.reconstructedSignatures = reconstructedSignatures;
        this.sisSignatures = sisSignatures;
        this.failureDetails = failureDetails;
    }
}
