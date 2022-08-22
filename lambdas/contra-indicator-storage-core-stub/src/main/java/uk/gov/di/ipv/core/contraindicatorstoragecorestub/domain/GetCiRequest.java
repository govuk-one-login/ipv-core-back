package uk.gov.di.ipv.core.contraindicatorstoragecorestub.domain;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
@SuppressWarnings("java:S116") // Field names should comply with a naming convention
public class GetCiRequest {
    private final String govuk_signin_journey_id;
    private final String user_id;

    public GetCiRequest(String govUkSigningJourneyId, String userId) {
        this.govuk_signin_journey_id = govUkSigningJourneyId;
        this.user_id = userId;
    }
}
