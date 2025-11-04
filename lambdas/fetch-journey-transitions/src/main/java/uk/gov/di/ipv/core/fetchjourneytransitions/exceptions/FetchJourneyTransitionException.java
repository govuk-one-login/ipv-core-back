package uk.gov.di.ipv.core.fetchjourneytransitions.exceptions;

import lombok.Getter;
import uk.gov.di.ipv.core.fetchjourneytransitions.domain.ErrorCode;

@Getter
public class FetchJourneyTransitionException extends Exception {
    private final ErrorCode errorCode;

    public FetchJourneyTransitionException(String errorMessage, ErrorCode rootCause) {
        super(errorMessage);
        this.errorCode = rootCause;
    }
}
