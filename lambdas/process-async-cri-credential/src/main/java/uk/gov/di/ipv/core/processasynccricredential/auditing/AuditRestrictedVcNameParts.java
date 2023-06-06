package uk.gov.di.ipv.core.processasynccricredential.auditing;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditRestricted;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditRestrictedVcNameParts implements AuditRestricted {
    @JsonProperty("nameParts")
    private final JsonNode nameParts;

    public AuditRestrictedVcNameParts(
            @JsonProperty(value = "nameParts", required = true) JsonNode nameParts) {
        this.nameParts = nameParts;
    }
}
