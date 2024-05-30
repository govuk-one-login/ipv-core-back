package uk.gov.di.ipv.core.library.domain.reverification;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public abstract class ReverificationBaseResponse {
    @JsonProperty protected final Boolean success;
    @JsonProperty protected final String sub;

    @JsonCreator
    protected ReverificationBaseResponse(
            @JsonProperty("sub") String sub, @JsonProperty("success") Boolean success) {
        this.success = success;
        this.sub = sub;
    }
}
