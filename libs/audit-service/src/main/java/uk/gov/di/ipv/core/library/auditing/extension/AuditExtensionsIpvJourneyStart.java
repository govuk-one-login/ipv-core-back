package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionsIpvJourneyStart(
        @JsonProperty("vtr") @JsonInclude(JsonInclude.Include.NON_NULL) List<String> vtr)
        implements AuditExtensions {

    public AuditExtensionsIpvJourneyStart(
            @JsonProperty(value = "vtr", required = false) List<String> vtr) {
        this.vtr = vtr;
    }
}
