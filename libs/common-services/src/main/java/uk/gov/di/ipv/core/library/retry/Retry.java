package uk.gov.di.ipv.core.library.retry;

import uk.gov.di.ipv.core.library.exceptions.MaxRetryAttemptsExceededException;
import uk.gov.di.ipv.core.library.exceptions.RetryException;

public class Retry {
    public static <T> T runTaskWithBackoff(
            Sleeper sleeper, int maxAttempts, int waitInterval, Task<T> task)
            throws RetryException, MaxRetryAttemptsExceededException {

        if (maxAttempts < 1) {
            throw new IllegalArgumentException("max attempts must be greater than 0");
        }
        var count = 0;
        while (count < maxAttempts) {
            var isLastAttempt = (count + 1) >= maxAttempts;
            var res = task.run(isLastAttempt);
            if (res.isPresent()) {
                return res.get();
            }
            if (isLastAttempt) {
                throw new MaxRetryAttemptsExceededException();
            }
            var backoff = (long) (waitInterval * Math.pow(2, count++));
            try {
                sleeper.sleep(backoff);
            } catch (InterruptedException e) {
                throw new RetryException(e);
            }
        }
        throw new MaxRetryAttemptsExceededException();
    }
}
