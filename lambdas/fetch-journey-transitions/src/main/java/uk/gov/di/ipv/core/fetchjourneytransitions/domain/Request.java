package uk.gov.di.ipv.core.fetchjourneytransitions.domain;

import uk.gov.di.ipv.core.fetchjourneytransitions.exceptions.RequestParseException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.helpers.ValidationHelper;

import java.time.Instant;

public record Request(
        Instant fromDate, Instant toDate, String ipvSessionId, String govukJourneyId) {

    @ExcludeFromGeneratedCoverageReport
    public static Request create(
            Instant fromDate, Instant toDate, String ipvSessionId, String govukJourneyId)
            throws RequestParseException {
        if (fromDate == null || toDate == null) {
            throw new RequestParseException("fromDate and toDate are required.");
        }
        if (!toDate.isAfter(fromDate)) {
            throw new RequestParseException("From date can not be further than to date.");
        }
        if (ipvSessionId != null && govukJourneyId != null) {
            throw new RequestParseException("Only one id must be presented.");
        }
        if (ipvSessionId != null && !ValidationHelper.isValidIpvSessionId(ipvSessionId)) {
            throw new RequestParseException("Invalid ipvSessionId format.");
        }
        if (govukJourneyId != null && govukJourneyId.length() > 256) {
            throw new RequestParseException("Invalid govukJourneyId format.");
        }

        return new Request(fromDate, toDate, ipvSessionId, govukJourneyId);
    }
}
