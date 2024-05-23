package uk.gov.di.ipv.core.library.domain.reverification;

import com.fasterxml.jackson.annotation.JsonCreator;
import lombok.Builder;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class ReverificationSuccessResponse extends ReverificationBaseResponse {

    @JsonCreator
    @Builder(builderMethodName = "successResponseBuilder")
    public ReverificationSuccessResponse(String sub) {
        super(sub, true);
    }
}
