package uk.gov.di.ipv.core.revokevcs.domain;

import lombok.Data;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.UserIdCriIdPair;

@ExcludeFromGeneratedCoverageReport
@Data
public class RevokeVcSuccess {
    private UserIdCriIdPair userIdCriIdPair;

    RevokeVcSuccess(UserIdCriIdPair userIdCriIdPair) {
        this.userIdCriIdPair = userIdCriIdPair;
    }
}
