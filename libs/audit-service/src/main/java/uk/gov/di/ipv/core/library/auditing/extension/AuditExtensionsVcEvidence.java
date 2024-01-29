package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditExtensionsVcEvidence implements AuditExtensions {
    @JsonProperty("iss")
    private final String iss;

    @JsonProperty("evidence")
    private final JsonNode evidence;

    public AuditExtensionsVcEvidence(
            @JsonProperty(value = "iss", required = false) String iss,
            @JsonProperty(value = "evidence", required = false) String evidence)
            throws JsonProcessingException {
        this.iss = iss;
        this.evidence = evidence == null ? null : new ObjectMapper().readTree(evidence);
    }
}
