package uk.gov.di.ipv.core.library.auditing;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import static uk.gov.di.ipv.core.library.helpers.LogHelper.GOVUK_SIGNIN_JOURNEY_ID_DEFAULT_VALUE;

@ExcludeFromGeneratedCoverageReport
@Getter
@EqualsAndHashCode
public class AuditEventUser {

    @JsonProperty(value = "user_id")
    private final String userId;

    @JsonProperty(value = "session_id")
    private final String sessionId;

    @JsonProperty(value = "govuk_signin_journey_id")
    private final String govukSigninJourneyId;

    @JsonProperty(value = "ip_address")
    private final String ipAddress;

    public AuditEventUser(
            @JsonProperty(value = "user_id") String userId,
            @JsonProperty(value = "session_id") String sessionId,
            @JsonProperty(value = "govuk_signin_journey_id") String govukSigninJourneyId,
            @JsonProperty(value = "ip_address") String ipAddress) {
        this.userId = userId;
        this.sessionId = sessionId;
        this.govukSigninJourneyId =
                StringUtils.isBlank(govukSigninJourneyId)
                        ? GOVUK_SIGNIN_JOURNEY_ID_DEFAULT_VALUE
                        : govukSigninJourneyId;
        this.ipAddress = ipAddress;
    }
}
