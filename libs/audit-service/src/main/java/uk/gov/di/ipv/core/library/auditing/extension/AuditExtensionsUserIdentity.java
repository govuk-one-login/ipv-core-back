package uk.gov.di.ipv.core.library.auditing.extension;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditExtensionsUserIdentity implements AuditExtensions {
    private final String levelOfConfidence;
    private final boolean ciFail;
    private final boolean hasMitigations;

    public AuditExtensionsUserIdentity(
            String levelOfConfidence, boolean ciFail, boolean hasMitigations) {
        this.levelOfConfidence = levelOfConfidence;
        this.ciFail = ciFail;
        this.hasMitigations = hasMitigations;
    }
}
