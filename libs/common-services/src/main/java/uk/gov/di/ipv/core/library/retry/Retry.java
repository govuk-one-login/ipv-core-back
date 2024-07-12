package uk.gov.di.ipv.core.library.retry;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.exceptions.NonRetryableException;
import uk.gov.di.ipv.core.library.exceptions.RetryableException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

public class Retry {

    private static final Logger LOGGER = LogManager.getLogger();

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

        Exception caught = null;
        for (var attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                return task.run();
            } catch (RetryableException e) {
                caught = e;
                LOGGER.warn(
                        LogHelper.buildErrorMessage(
                                "retryable task failed on attempt " + attempt, e));
            }
            if (attempt < maxAttempts) {
                var backoff = (long) (waitInterval * Math.pow(2, attempt - (double) 1));
                sleeper.sleep(backoff);
            }
        }
        throw new NonRetryableException("Max attempts reached for task: " + maxAttempts, caught);
    }
}
