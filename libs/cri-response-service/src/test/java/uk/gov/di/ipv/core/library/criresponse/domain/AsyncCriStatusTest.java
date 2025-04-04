package uk.gov.di.ipv.core.library.criresponse.domain;

import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.enums.Vot;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;

@ExtendWith(MockitoExtension.class)
class AsyncCriStatusTest {
    @ParameterizedTest
    @MethodSource("DcmawAsyncSameSessionJourneysAndCriResponseItemStatuses")
    void getJourneyForAwaitingVcShouldReturnCorrectJourneyForDcmawAsyncSameSession(
            String incompleteStatus, String expectedJourney) {
        // Arrange
        var asyncCriStatus =
                new AsyncCriStatus(DCMAW_ASYNC, incompleteStatus, false, false, false, Vot.P1);

        // Act
        var journeyResponse = asyncCriStatus.getJourneyForAwaitingVc(true);

        // Assert
        assertEquals(expectedJourney, journeyResponse.getJourney());
    }

    static Stream<Arguments> DcmawAsyncSameSessionJourneysAndCriResponseItemStatuses() {
        return Stream.of(
                Arguments.of(AsyncCriStatus.STATUS_ABANDON, "/journey/abandon"),
                Arguments.of(AsyncCriStatus.STATUS_ERROR, "/journey/error"),
                Arguments.of("not a status", "/journey/error"));
    }

    void getJourneyForAwaitingVcShouldReturnCorrectJourneyForDcmawAsyncSameSession() {
        // Arrange
        var asyncCriStatus =
                new AsyncCriStatus(
                        DCMAW_ASYNC, AsyncCriStatus.STATUS_PENDING, false, false, false, Vot.P1);

        // Act
        var journeyResponse = asyncCriStatus.getJourneyForAwaitingVc(true);

        // Assert
        assertNull(journeyResponse.getJourney());
    }

    @ParameterizedTest
    @MethodSource("F2fFailJourneys")
    void getF2FFailJourneyShouldReturnCorrectJourney(Vot targetVot, String expectedJourney) {
        // Arrange
        var asyncCriStatus =
                new AsyncCriStatus(
                        F2F, AsyncCriStatus.STATUS_ERROR, false, false, false, targetVot);

        // Act
        var journeyResponse = asyncCriStatus.getJourneyForAwaitingVc(false);

        // Assert
        assertEquals(expectedJourney, journeyResponse.getJourney());
    }

    static Stream<Arguments> F2fFailJourneys() {
        return Stream.of(
                Arguments.of(Vot.P1, "/journey/f2f-fail-p1"),
                Arguments.of(Vot.P2, "/journey/f2f-fail-p2"));
    }

    @ParameterizedTest
    @MethodSource("F2fJourneysAndCriResponseItemStatuses")
    void getJourneyForAwaitingVcShouldReturnCorrectJourneyForF2f(
            String incompleteStatus, String expectedJourney) {
        // Arrange
        var asyncCriStatus = new AsyncCriStatus(F2F, incompleteStatus, false, false, false, Vot.P1);

        // Act
        var journeyResponse = asyncCriStatus.getJourneyForAwaitingVc(false);

        // Assert
        assertEquals(expectedJourney, journeyResponse.getJourney());
    }

    static Stream<Arguments> F2fJourneysAndCriResponseItemStatuses() {
        return Stream.of(
                Arguments.of(AsyncCriStatus.STATUS_PENDING, "/journey/pending"),
                Arguments.of(AsyncCriStatus.STATUS_ABANDON, "/journey/f2f-fail-p1"),
                Arguments.of(AsyncCriStatus.STATUS_ERROR, "/journey/f2f-fail-p1"),
                Arguments.of("not a status", "/journey/error"));
    }
}
