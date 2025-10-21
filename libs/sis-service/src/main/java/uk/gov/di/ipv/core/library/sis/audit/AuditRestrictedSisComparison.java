package uk.gov.di.ipv.core.library.sis.audit;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestricted;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditRestrictedSisComparison implements AuditRestricted {

    private final List<String> reconstructedSignatures;
    private final List<String> sisSignatures;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private final String failureDetails;

    public AuditRestrictedSisComparison(
            List<String> reconstructedSignatures,
            List<String> sisSignatures,
            String failureDetails) {
        this.reconstructedSignatures = reconstructedSignatures;
        this.sisSignatures = sisSignatures;
        this.failureDetails = failureDetails;
    }
}
