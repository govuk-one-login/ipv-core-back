package uk.gov.di.ipv.core.revokevcs.domain;

import lombok.Data;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.UserIdCriIdPair;

@ExcludeFromGeneratedCoverageReport
@Data
public class RevokeVcFailure {
    private final UserIdCriIdPair userIdCriIdPair;
    private final String errorMessage;

    RevokeVcFailure(UserIdCriIdPair userIdCriIdPair, String errorMessage) {
        this.userIdCriIdPair = userIdCriIdPair;
        this.errorMessage = errorMessage;
    }
}
