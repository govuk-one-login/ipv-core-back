package uk.gov.di.ipv.core.library.cimit.domain;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

import java.util.List;

@Data
public class PostCiMitigationRequest {
    @SerializedName(value = "govuk_signin_journey_id")
    private final String govukSigninJourneyId;

    @SerializedName(value = "ip_address")
    private final String ipAddress;

    @SerializedName(value = "signed_jwts")
    private final List<String> signedJwtList;
}
