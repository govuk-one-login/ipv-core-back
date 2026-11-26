package uk.gov.di.ipv.core.storetriagedata.triage;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.persistence.item.DynamicRoutingState;
import uk.gov.di.ipv.core.storetriagedata.exceptions.InvalidTriageDataException;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LiveInUkQuestionTest {
    private final LiveInUkQuestion question = new LiveInUkQuestion();

    @Test
    void ukAnswerShouldSetLivesInUkTrue() throws Exception {
        // Arrange
        var state = new DynamicRoutingState();

        // Act
        question.apply(List.of("uk"), state);

        // Assert
        assertTrue(state.getLivesInUk());
    }

    @Test
    void internationalAnswerShouldSetLivesInUkFalse() throws Exception {
        // Arrange
        var state = new DynamicRoutingState();

        // Act
        question.apply(List.of("international"), state);

        // Assert
        assertFalse(state.getLivesInUk());
    }

    @Test
    void shouldRejectUnrecognisedAnswerAndLeaveStateUnchanged() {
        // Arrange
        var state = new DynamicRoutingState();

        // Act and Assert
        var exception =
                assertThrows(
                        InvalidTriageDataException.class,
                        () -> question.apply(List.of("mars"), state));
        assertEquals(ErrorResponse.INVALID_TRIAGE_ANSWER, exception.getErrorResponse());
        assertNull(state.getLivesInUk());
    }

    @Test
    void shouldRejectNullAnswers() {
        // Arrange
        var state = new DynamicRoutingState();

        // Act and Assert
        assertThrows(InvalidTriageDataException.class, () -> question.apply(null, state));
        assertNull(state.getLivesInUk());
    }

    @Test
    void shouldRejectEmptyAnswers() {
        // Arrange
        var state = new DynamicRoutingState();

        // Act and Assert
        assertThrows(InvalidTriageDataException.class, () -> question.apply(List.of(), state));
        assertNull(state.getLivesInUk());
    }

    @Test
    void shouldRejectMultipleAnswers() {
        // Arrange
        var state = new DynamicRoutingState();

        // Act and Assert
        assertThrows(
                InvalidTriageDataException.class,
                () -> question.apply(List.of("uk", "international"), state));
        assertNull(state.getLivesInUk());
    }
}
