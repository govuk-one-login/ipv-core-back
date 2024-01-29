package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditExtensionErrorMessage implements AuditExtensions {

    @JsonProperty("error_message")
    private final String errorMessage;

    @JsonCreator
    public AuditExtensionErrorMessage(
            @JsonProperty(value = "error_message", required = true) String errorMessage) {
        this.errorMessage = errorMessage;
    }
}
