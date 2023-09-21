package uk.gov.di.ipv.core.processasynccricredential.auditing;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditRestricted;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditRestrictedVc implements AuditRestricted {
    @JsonProperty("nameParts")
    private final JsonNode nameParts;

    @JsonProperty("docExpiryDate")
    private String docExpiryDate;

    public AuditRestrictedVc(
            @JsonProperty(value = "nameParts", required = true) JsonNode nameParts,
            @JsonProperty(value = "docExpiryDate", required = true) String docExpiryDate) {
        this.nameParts = nameParts;
        this.docExpiryDate = docExpiryDate;
    }

    public AuditRestrictedVc(
            @JsonProperty(value = "nameParts", required = true) JsonNode nameParts) {
        this.nameParts = nameParts;
    }
}
