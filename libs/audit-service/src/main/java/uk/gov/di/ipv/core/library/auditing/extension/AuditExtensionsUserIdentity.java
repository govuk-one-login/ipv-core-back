package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionsUserIdentity(
        @JsonProperty String levelOfConfidence,
        @JsonProperty boolean ciFail,
        @JsonProperty boolean hasMitigations,
        @JsonInclude(JsonInclude.Include.NON_NULL) @JsonProperty(EXIT_CODE_NAME)
                List<String> exitCode)
        implements AuditExtensions {
    private static final String EXIT_CODE_NAME = "exit_code";

    @JsonCreator
    public AuditExtensionsUserIdentity(
            @JsonProperty String levelOfConfidence,
            @JsonProperty boolean ciFail,
            @JsonProperty boolean hasMitigations,
            @JsonProperty(value = EXIT_CODE_NAME) List<String> exitCode) {
        this.levelOfConfidence = levelOfConfidence;
        this.ciFail = ciFail;
        this.hasMitigations = hasMitigations;
        this.exitCode = exitCode;
    }
}
