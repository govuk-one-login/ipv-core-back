package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditExtensionsReceivedVcEvidence extends AuditExtensionsVcEvidence {
    @JsonProperty("successful")
    private final boolean successful;

    public AuditExtensionsReceivedVcEvidence(
            @JsonProperty(value = "iss", required = false) String iss,
            @JsonProperty(value = "evidence", required = false) String evidence,
            @JsonProperty(value = "successful", required = false) boolean successful)
            throws JsonProcessingException {
        super(iss, evidence);
        this.successful = successful;
    }
}
