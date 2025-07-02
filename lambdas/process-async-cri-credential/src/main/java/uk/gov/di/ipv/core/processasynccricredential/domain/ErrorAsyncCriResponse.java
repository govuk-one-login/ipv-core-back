package uk.gov.di.ipv.core.processasynccricredential.domain;

import lombok.Builder;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class ErrorAsyncCriResponse extends BaseAsyncCriResponse {
    private final String error;
    private final String errorDescription;

    @Builder
    private ErrorAsyncCriResponse(
            String userId,
            String oauthState,
            String error,
            String errorDescription,
            String journeyId) {
        super(userId, oauthState, journeyId);
        this.error = error;
        this.errorDescription = errorDescription;
    }
}
