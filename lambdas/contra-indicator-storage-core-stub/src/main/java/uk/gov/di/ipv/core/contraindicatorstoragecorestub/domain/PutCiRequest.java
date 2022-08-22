package uk.gov.di.ipv.core.contraindicatorstoragecorestub.domain;

import com.google.gson.annotations.SerializedName;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@Getter
@ExcludeFromGeneratedCoverageReport
public class PutCiRequest {
    @SerializedName(value = "govuk_signin_journey_id")
    private final String govukSigninJourneyId;

    @SerializedName(value = "signed_jwt")
    private final String signedJwt;

    public PutCiRequest(String govUkSigningJourneyId, String signedJwt) {
        this.govukSigninJourneyId = govUkSigningJourneyId;
        this.signedJwt = signedJwt;
    }
}
