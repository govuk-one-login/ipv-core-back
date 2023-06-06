package uk.gov.di.ipv.core.processasynccricredential.domain;

import lombok.Builder;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Getter
public class SuccessAsyncCriResponse extends BaseAsyncCriResponse {
    private final List<String> verifiableCredentialJWTs;

    @Builder
    private SuccessAsyncCriResponse(
            String credentialIssuer,
            String userId,
            String oauthState,
            List<String> verifiableCredentialJWTs) {
        super(credentialIssuer, userId, oauthState);
        this.verifiableCredentialJWTs = verifiableCredentialJWTs;
    }
}
