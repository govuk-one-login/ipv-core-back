package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditExtensionCriId implements AuditExtensions {

    @JsonProperty("cri")
    private final String criId;

    @JsonCreator
    public AuditExtensionCriId(@JsonProperty(value = "cri", required = true) String criId) {
        this.criId = criId;
    }
}
