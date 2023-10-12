package uk.gov.di.ipv.core.processasynccricredential.auditing;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditRestricted;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditRestrictedVc implements AuditRestricted {
    @JsonProperty("name")
    private final JsonNode name;

    @JsonProperty("docExpiryDate")
    private String docExpiryDate;

    public AuditRestrictedVc(
            @JsonProperty(value = "name", required = true) JsonNode name,
            @JsonProperty(value = "docExpiryDate", required = true) String docExpiryDate) {
        this.name = name;
        this.docExpiryDate = docExpiryDate;
    }

    public AuditRestrictedVc(@JsonProperty(value = "name", required = true) JsonNode name) {
        this.name = name;
    }
}
