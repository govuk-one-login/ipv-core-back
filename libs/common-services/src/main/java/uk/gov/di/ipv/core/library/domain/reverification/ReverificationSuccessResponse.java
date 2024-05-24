package uk.gov.di.ipv.core.library.domain.reverification;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class ReverificationSuccessResponse extends ReverificationBaseResponse {

    @JsonCreator
    @Builder(builderMethodName = "successResponseBuilder")
    public ReverificationSuccessResponse(@JsonProperty("sub") String sub) {
        super(sub, true);
    }
}
