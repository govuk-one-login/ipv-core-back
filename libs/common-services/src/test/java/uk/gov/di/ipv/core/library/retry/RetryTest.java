package uk.gov.di.ipv.core.library.retry;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.exceptions.NonRetryableException;
import uk.gov.di.ipv.core.library.exceptions.RetryableException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class RetryTest {

    @Mock private Sleeper mockSleeper;

    private final RetryableTask<Boolean> testTaskSucceedsOnLastAttemptWithRetryableExceptions =
            (isLastAttempt) -> {
                if (isLastAttempt) {
                    return Optional.of(true);
                }
                throw new RetryableException("a retryable exception");
            };
    private final RetryableTask<Boolean> testTaskSucceedsOnLastAttempt =
            (isLastAttempt) -> {
                if (isLastAttempt) {
                    return Optional.of(true);
                }
                return Optional.empty();
            };

    private final RetryableTask<Boolean> testTaskFailedWithNonRetryableException =
            (isLastAttempt) -> {
                throw new NonRetryableException("a non retryable exception");
            };

    private final RetryableTask<Boolean> testTaskFailedWitRetryableException =
            (isLastAttempt) -> {
                throw new RetryableException("a retryable exception");
            };

    @Test
    void shouldThrowIllegalArgumentExceptionWhenAttemptsLessThanOne() {
        var exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () ->
                                Retry.runTaskWithBackoff(
                                        mockSleeper, 0, 100, testTaskSucceedsOnLastAttempt));

        assertEquals("Max attempts must be greater than 0", exception.getMessage());
    }

    @Test
    void shouldThrowIllegalArgumentExceptionWhenWaitIntervalIsLessThanOne() {
        var exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () ->
                                Retry.runTaskWithBackoff(
                                        mockSleeper, 5, -1, testTaskSucceedsOnLastAttempt));

        assertEquals("Wait interval must be greater than 0", exception.getMessage());
    }

    @Test
    void shouldSleepForCorrectAmountOfTime()
            throws RetryableException, NonRetryableException, InterruptedException {
        var res = Retry.runTaskWithBackoff(mockSleeper, 10, 1, testTaskSucceedsOnLastAttempt);

        var inOrder = inOrder(mockSleeper);
        // should be 9 sleeps after the initial attempt
        inOrder.verify(mockSleeper, times(1)).sleep(1);
        inOrder.verify(mockSleeper, times(1)).sleep(2);
        inOrder.verify(mockSleeper, times(1)).sleep(4);
        inOrder.verify(mockSleeper, times(1)).sleep(8);
        inOrder.verify(mockSleeper, times(1)).sleep(16);
        inOrder.verify(mockSleeper, times(1)).sleep(32);
        inOrder.verify(mockSleeper, times(1)).sleep(64);
        inOrder.verify(mockSleeper, times(1)).sleep(128);
        inOrder.verify(mockSleeper, times(1)).sleep(256);
        inOrder.verifyNoMoreInteractions();

        assertTrue(res);
    }

    @Test
    void shouldSleepForCorrectAmountOfTimeWhenThrowingRetryableException()
            throws RetryableException, NonRetryableException, InterruptedException {
        var res =
                Retry.runTaskWithBackoff(
                        mockSleeper, 4, 2, testTaskSucceedsOnLastAttemptWithRetryableExceptions);

        var inOrder = inOrder(mockSleeper);
        // should be 9 sleeps after the initial attempt
        inOrder.verify(mockSleeper, times(1)).sleep(2);
        inOrder.verify(mockSleeper, times(1)).sleep(4);
        inOrder.verify(mockSleeper, times(1)).sleep(8);
        inOrder.verifyNoMoreInteractions();

        assertTrue(res);
    }

    @Test
    void shouldNotSleepIfFirstAttemptSuccessful()
            throws RetryableException, NonRetryableException, InterruptedException {
        var res =
                Retry.runTaskWithBackoff(
                        mockSleeper,
                        10,
                        1,
                        (isLastAttempt) -> {
                            return Optional.of(1);
                        });

        assertEquals(1, res);
        verify(mockSleeper, never()).sleep(anyLong());
    }

    @Test
    void shouldThrowRetryExceptionIfNeverSuccessful() throws InterruptedException {
        var exception =
                assertThrows(
                        NonRetryableException.class,
                        () ->
                                Retry.runTaskWithBackoff(
                                        mockSleeper, 5, 5, testTaskFailedWitRetryableException));

        assertEquals("Max attempts reached for task: 5", exception.getMessage());
        verify(mockSleeper, times(4)).sleep(anyLong());
    }

    @Test
    void shouldThrowInterruptedExceptionIfThrownBySleeper() throws InterruptedException {
        doThrow(new InterruptedException()).when(mockSleeper).sleep(anyLong());

        assertThrows(
                InterruptedException.class,
                () -> Retry.runTaskWithBackoff(mockSleeper, 5, 5, testTaskSucceedsOnLastAttempt));
    }

    @Test
    void shouldThrowRetryExceptionIfThrownByTask() throws InterruptedException {
        assertThrows(
                NonRetryableException.class,
                () ->
                        Retry.runTaskWithBackoff(
                                mockSleeper, 10, 1, testTaskFailedWithNonRetryableException));

        verify(mockSleeper, never()).sleep(anyLong());
    }
}
