package uk.gov.di.ipv.core.library.retry;

import uk.gov.di.ipv.core.library.exceptions.RetryException;

public class Retry {

    private Retry() {
        throw new IllegalStateException("Utility class");
    }

    public static <T> T runTaskWithBackoff(
            Sleeper sleeper, int maxAttempts, int waitInterval, RetryableTask<T> task)
            throws RetryException, InterruptedException {

        if (maxAttempts < 1) {
            throw new IllegalArgumentException("max attempts must be greater than 0");
        }
        if (waitInterval < 1) {
            throw new IllegalArgumentException("wait interval must be greater than 0");
        }
        var count = 0;
        while (count < maxAttempts) {
            var isLastAttempt = (count + 1) >= maxAttempts;
            var res = task.run(isLastAttempt);
            if (res.isPresent()) {
                return res.get();
            }
            if (isLastAttempt) {
                throw new RetryException("max attempts reached for task: " + maxAttempts);
            }
            var backoff = (long) (waitInterval * Math.pow(2, count++));
            sleeper.sleep(backoff);
        }
        throw new RetryException("max attempts reached for task: " + maxAttempts);
    }
}
