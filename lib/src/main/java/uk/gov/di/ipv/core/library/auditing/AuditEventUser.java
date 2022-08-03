package uk.gov.di.ipv.core.library.auditing;

import com.amazonaws.util.StringUtils;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import static uk.gov.di.ipv.core.library.helpers.LogHelper.GOVUK_SIGNIN_JOURNEY_ID_DEFAULT_VALUE;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditEventUser {

    @JsonProperty(value = "user_id")
    private final String userId;

    @JsonProperty(value = "session_id")
    private final String sessionId;

    @JsonProperty(value = "govuk_signin_journey_id")
    private final String govukSigninJourneyId;

    public AuditEventUser(
            @JsonProperty(value = "user_id", required = false) String userId,
            @JsonProperty(value = "session_id", required = false) String sessionId,
            @JsonProperty(value = "govuk_signin_journey_id", required = false)
                    String govukSigninJourneyId) {
        this.userId = userId;
        this.sessionId = sessionId;
        if (StringUtils.isNullOrEmpty(govukSigninJourneyId)) {
            this.govukSigninJourneyId = GOVUK_SIGNIN_JOURNEY_ID_DEFAULT_VALUE;
        } else {
            this.govukSigninJourneyId = govukSigninJourneyId;
        }
    }
}
