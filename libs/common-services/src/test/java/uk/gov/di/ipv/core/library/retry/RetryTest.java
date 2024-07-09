package uk.gov.di.ipv.core.library.retry;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.exceptions.RetryException;

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

    private RetryableTask<Boolean> testTask =
            new RetryableTask<Boolean>() {
                @Override
                public Optional<Boolean> run(boolean isLastAttempt)
                        throws RetryException, InterruptedException {
                    if (isLastAttempt) {
                        return Optional.of(true);
                    }
                    return Optional.empty();
                }
            };

    private RetryableTask<Boolean> testTaskWithException =
            new RetryableTask<Boolean>() {
                @Override
                public Optional<Boolean> run(boolean isLastAttempt)
                        throws RetryException, InterruptedException {
                    throw new RetryException("an exception");
                }
            };

    private RetryableTask<Boolean> testTaskFailed =
            new RetryableTask<Boolean>() {
                @Override
                public Optional<Boolean> run(boolean isLastAttempt)
                        throws RetryException, InterruptedException {
                    return Optional.empty();
                }
            };

    @Test
    void shouldThrowIllegalArgumentExceptionWhenAttemptsLessThanOne() {
        var exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> Retry.runTaskWithBackoff(mockSleeper, 0, 100, testTask));

        assertEquals("max attempts must be greater than 0", exception.getMessage());
    }

    @Test
    void shouldThrowIllegalArgumentExceptionWhenWaitIntervalIsLessThanOne() {
        var exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> Retry.runTaskWithBackoff(mockSleeper, 5, -1, testTask));

        assertEquals("wait interval must be greater than 0", exception.getMessage());
    }

    @Test
    void shouldSleepForCorrectAmountOfTime() throws RetryException, InterruptedException {
        var res = Retry.runTaskWithBackoff(mockSleeper, 10, 1, testTask);

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
    void shouldNotSleepIfFirstAttemptSuccessful() throws RetryException, InterruptedException {
        var res =
                Retry.runTaskWithBackoff(
                        mockSleeper,
                        10,
                        1,
                        new RetryableTask<Integer>() {
                            @Override
                            public Optional<Integer> run(boolean isLastAttempt)
                                    throws RetryException, InterruptedException {
                                return Optional.of(1);
                            }
                        });

        assertEquals(1, res);
        verify(mockSleeper, never()).sleep(anyLong());
    }

    @Test
    void shouldThrowRetryExceptionIfNeverSuccessful() throws InterruptedException {
        var exception =
                assertThrows(
                        RetryException.class,
                        () -> Retry.runTaskWithBackoff(mockSleeper, 5, 5, testTaskFailed));

        assertEquals("max attempts reached for task: 5", exception.getMessage());
        verify(mockSleeper, times(4)).sleep(anyLong());
    }

    @Test
    void shouldThrowInterruptedExceptionIfThrownBySleeper() throws InterruptedException {
        doThrow(new InterruptedException()).when(mockSleeper).sleep(anyLong());

        assertThrows(
                InterruptedException.class,
                () -> Retry.runTaskWithBackoff(mockSleeper, 5, 5, testTaskFailed));
    }

    @Test
    void shouldThrowRetryExceptionIfThrownByTask() throws InterruptedException {
        assertThrows(
                RetryException.class,
                () -> Retry.runTaskWithBackoff(mockSleeper, 10, 1, testTaskWithException));

        verify(mockSleeper, never()).sleep(anyLong());
    }
}
