package uk.gov.di.ipv.core.library.retry;

import uk.gov.di.ipv.core.library.exceptions.RetryException;

import java.util.Optional;

public interface RetryableTask<T> {
    public Optional<T> run(boolean isLastAttempt) throws RetryException;
}
