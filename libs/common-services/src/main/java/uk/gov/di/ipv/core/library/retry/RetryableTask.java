package uk.gov.di.ipv.core.library.retry;

import uk.gov.di.ipv.core.library.exceptions.RetryException;

import java.util.Optional;

public interface RetryableTask<T> {
    /*
     * Interface for a retryable task - the implementation should return
     * an Optional.empty() to indicate that the task should be retried and
     * throw a RetryException if any errors occur
     */
    public Optional<T> run(boolean isLastAttempt) throws RetryException, InterruptedException;
}
