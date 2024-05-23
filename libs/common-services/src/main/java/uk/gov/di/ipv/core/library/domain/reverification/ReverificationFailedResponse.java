package uk.gov.di.ipv.core.library.domain.reverification;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Builder
public class ReverificationFailedResponse extends ReverificationBaseResponse {
    @JsonProperty private final String error_code;
    @JsonProperty private final String error_description;

    @JsonCreator
    @Builder(builderMethodName = "failedResponseBuilder")
    public ReverificationFailedResponse(
            String sub,
            @JsonProperty("error_code") String error_code,
            @JsonProperty("error_description") String error_description) {
        super(sub, false);
        this.error_code = error_code;
        this.error_description = error_description;
    }
}
