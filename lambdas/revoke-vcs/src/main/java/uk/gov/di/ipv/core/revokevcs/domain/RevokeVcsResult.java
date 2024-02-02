package uk.gov.di.ipv.core.revokevcs.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.UserIdCriIdPair;

import java.util.ArrayList;
import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Data
public class RevokeVcsResult {
    @JsonProperty("successes")
    private List<RevokeVcSuccess> successes = new ArrayList<>();

    @JsonProperty("failures")
    private List<RevokeVcFailure> failures = new ArrayList<>();

    public void addSuccess(UserIdCriIdPair userIdCriIdPair) {
        successes.add(new RevokeVcSuccess(userIdCriIdPair));
    }

    public void addFailure(UserIdCriIdPair userIdCriIdPair, Throwable cause) {
        failures.add(new RevokeVcFailure(userIdCriIdPair, cause.getMessage()));
    }
}
