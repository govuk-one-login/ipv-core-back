package uk.gov.di.ipv.core.library.retry;

import uk.gov.di.ipv.core.library.exceptions.NonRetryableException;
import uk.gov.di.ipv.core.library.exceptions.RetryableException;

public class Retry {

    private Retry() {
        throw new IllegalStateException("Utility class");
    }

    public static <T> T runTaskWithBackoff(
            Sleeper sleeper, int maxAttempts, int waitInterval, RetryableTask<T> task)
            throws NonRetryableException, InterruptedException {

        if (maxAttempts < 1) {
            throw new IllegalArgumentException("Max attempts must be greater than 0");
        }
        if (waitInterval < 1) {
            throw new IllegalArgumentException("Wait interval must be greater than 0");
        }

        for (var attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                var res = task.run(attempt == maxAttempts);
                if (res.isPresent()) {
                    return res.get();
                }
            } catch (RetryableException e) {
            }
            if (attempt < maxAttempts) {
                var backoff = (long) (waitInterval * Math.pow(2, attempt - 1));
                sleeper.sleep(backoff);
            }
        }
        throw new NonRetryableException("Max attempts reached for task: " + maxAttempts);
    }
}
