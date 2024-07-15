package uk.gov.di.ipv.core.library.retry;

import uk.gov.di.ipv.core.library.exceptions.NonRetryableException;
import uk.gov.di.ipv.core.library.exceptions.RetryableException;

public interface RetryableTask<T> {
    /*
     * Interface for a retryable task - the implementation should return a result or
     * throw a RetryableException if the task can be retried or
     * thow a NonRetryableException if the task cannot be retried
     */
    public T run() throws RetryableException, NonRetryableException;
}
