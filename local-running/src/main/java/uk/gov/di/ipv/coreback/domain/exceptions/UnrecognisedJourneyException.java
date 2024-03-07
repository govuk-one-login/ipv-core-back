package uk.gov.di.ipv.coreback.domain.exceptions;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class UnrecognisedJourneyException extends RuntimeException {
    public UnrecognisedJourneyException(String message) {
        super(message);
    }
}
