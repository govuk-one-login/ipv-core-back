package uk.gov.di.ipv.core.library.domain;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class GetCiRequest {
    @SerializedName(value = "govuk_signin_journey_id")
    private final String govukSigninJourneyId;

    @SerializedName(value = "user_id")
    private final String userId;
}
