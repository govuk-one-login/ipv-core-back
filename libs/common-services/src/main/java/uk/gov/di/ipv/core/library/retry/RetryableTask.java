package uk.gov.di.ipv.core.library.retry;

import uk.gov.di.ipv.core.library.exceptions.NonRetryableException;
import uk.gov.di.ipv.core.library.exceptions.RetryableException;

import java.util.Optional;

public interface RetryableTask<T> {
    /*
     * Interface for a retryable task - the implementation should return
     * an Optional with the successful value to return or
     * throw a RetryableException or return an empty option if the task can be retried or
     * thow a NonRetryableException if the task cannot be retried
     */
    public Optional<T> run(boolean isLastAttempt) throws RetryableException, NonRetryableException;
}
