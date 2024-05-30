package uk.gov.di.ipv.core.library.domain.reverification;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class ReverificationFailedResponse extends ReverificationBaseResponse {
    @JsonProperty private final String errorCode;
    @JsonProperty private final String errorDescription;

    @JsonCreator
    @Builder(builderMethodName = "failedResponseBuilder")
    public ReverificationFailedResponse(
            @JsonProperty("sub") String sub,
            @JsonProperty("error_code") String errorCode,
            @JsonProperty("error_description") String errorDescription) {
        super(sub, false);
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
    }
}
