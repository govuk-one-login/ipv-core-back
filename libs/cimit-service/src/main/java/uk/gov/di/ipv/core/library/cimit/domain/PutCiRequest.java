package uk.gov.di.ipv.core.library.cimit.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class PutCiRequest {
    @JsonProperty("govuk_signin_journey_id")
    private final String govukSigninJourneyId;

    @JsonProperty("ip_address")
    private final String ipAddress;

    @JsonProperty("signed_jwt")
    private final String signedJwt;
}
