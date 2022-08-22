package uk.gov.di.ipv.core.contraindicatorstoragecorestub.domain;

import com.google.gson.annotations.SerializedName;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class GetCiRequest {
    @SerializedName(value = "govuk_signin_journey_id")
    private final String govukSigninJourneyId;

    @SerializedName(value = "user_id")
    private final String userId;

    public GetCiRequest(String govUkSigningJourneyId, String userId) {
        this.govukSigninJourneyId = govUkSigningJourneyId;
        this.userId = userId;
    }
}
