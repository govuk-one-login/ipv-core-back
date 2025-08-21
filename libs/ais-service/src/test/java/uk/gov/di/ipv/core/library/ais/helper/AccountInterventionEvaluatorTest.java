package uk.gov.di.ipv.core.library.ais.helper;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.ipv.core.library.dto.AccountInterventionState;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AccountInterventionEvaluatorTest {

    @ParameterizedTest
    @ArgumentsSource(InvalidInitialAccountInterventionArgumentsProvider.class)
    void shouldReturnTrueWhenProvideInvalidAccountIntervention(
            AccountInterventionState accountInterventionState) {
        assertTrue(
                AccountInterventionEvaluator.isInitialAccountInterventionDetected(
                        accountInterventionState));
    }

    @ParameterizedTest
    @MethodSource("getValidAccountInterventionState")
    void shouldReturnFalseWhenProvideValidAccountIntervention(
            AccountInterventionState accountInterventionState) {
        assertFalse(
                AccountInterventionEvaluator.isInitialAccountInterventionDetected(
                        accountInterventionState));
    }

    private static Stream<Arguments> getValidAccountInterventionState() {
        return Stream.of(
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(true)
                                .isReproveIdentity(true)
                                .isResetPassword(false)
                                .build()),
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(false)
                                .isReproveIdentity(true)
                                .isResetPassword(false)
                                .build()),
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(false)
                                .isReproveIdentity(false)
                                .isResetPassword(false)
                                .build()));
    }

    @ParameterizedTest
    @ArgumentsSource(InvalidMidJourneyAccountInterventionArgumentsProvider.class)
    void shouldReturnTrueWhenProvideValidMidJourneyAccountInterventionStates(
            AccountInterventionState initialAccountIntervention,
            AccountInterventionState midJourneyAccountInterventionState) {
        assertTrue(
                AccountInterventionEvaluator.isMidJourneyAccountInterventionDetected(
                        initialAccountIntervention, midJourneyAccountInterventionState));
    }
}
