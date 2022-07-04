package uk.gov.di.ipv.core.library.auditing;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
@Builder
public class AuditExtensionErrorParams implements AuditExtensions {
    @JsonProperty("error_code")
    private final String errorCode;

    @JsonProperty("error_description")
    private final String errorDescription;

    @JsonCreator
    public AuditExtensionErrorParams(
            @JsonProperty(value = "error_code", required = false) String errorCode,
            @JsonProperty(value = "error_description", required = false) String errorDescription) {
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
    }
}
