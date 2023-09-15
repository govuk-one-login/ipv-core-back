package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditExtensionsUserIdentity implements AuditExtensions {
    @JsonProperty("levelOfConfidence")
    private final String levelOfConfidence;

    public AuditExtensionsUserIdentity(
            @JsonProperty(value = "levelOfConfidence") String levelOfConfidence) {
        this.levelOfConfidence = levelOfConfidence;
    }
}
