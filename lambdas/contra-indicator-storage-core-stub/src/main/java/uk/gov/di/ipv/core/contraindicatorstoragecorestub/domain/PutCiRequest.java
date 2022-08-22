package uk.gov.di.ipv.core.contraindicatorstoragecorestub.domain;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
@SuppressWarnings("java:S116") // Field names should comply with a naming convention
public class PutCiRequest {
    private final String govuk_signin_journey_id;
    private final String signed_jwt;

    public PutCiRequest(String govUkSigningJourneyId, String signedJwt) {
        this.govuk_signin_journey_id = govUkSigningJourneyId;
        this.signed_jwt = signedJwt;
    }
}
