package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.service.CriResponseService;

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
        var asyncCriStatus = new AsyncCriStatus(DCMAW_ASYNC, incompleteStatus, false, false);

        // Act
        var journeyResponse = asyncCriStatus.getJourneyForAwaitingVc(true);

        // Assert
        assertEquals(expectedJourney, journeyResponse.getJourney());
    }

    static Stream<Arguments> DcmawAsyncSameSessionJourneysAndCriResponseItemStatuses() {
        return Stream.of(
                Arguments.of(CriResponseService.STATUS_ABANDON, "/journey/abandon"),
                Arguments.of(CriResponseService.STATUS_ERROR, "/journey/error"),
                Arguments.of("not a status", "/journey/error"));
    }

    void getJourneyForAwaitingVcShouldReturnCorrectJourneyForDcmawAsyncSameSession() {
        // Arrange
        var asyncCriStatus =
                new AsyncCriStatus(DCMAW_ASYNC, CriResponseService.STATUS_PENDING, false, false);

        // Act
        var journeyResponse = asyncCriStatus.getJourneyForAwaitingVc(true);

        // Assert
        assertNull(journeyResponse.getJourney());
    }

    @ParameterizedTest
    @MethodSource("F2fJourneysAndCriResponseItemStatuses")
    void getJourneyForAwaitingVcShouldReturnCorrectJourneyForF2f(
            String incompleteStatus, String expectedJourney) {
        // Arrange
        var asyncCriStatus = new AsyncCriStatus(F2F, incompleteStatus, false, false);

        // Act
        var journeyResponse = asyncCriStatus.getJourneyForAwaitingVc(false);

        // Assert
        assertEquals(expectedJourney, journeyResponse.getJourney());
    }

    static Stream<Arguments> F2fJourneysAndCriResponseItemStatuses() {
        return Stream.of(
                Arguments.of(CriResponseService.STATUS_PENDING, "/journey/pending"),
                Arguments.of(CriResponseService.STATUS_ABANDON, "/journey/f2f-fail"),
                Arguments.of(CriResponseService.STATUS_ERROR, "/journey/f2f-fail"),
                Arguments.of("not a status", "/journey/error"));
    }
}
