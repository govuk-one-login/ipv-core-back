package uk.gov.di.ipv.core.library.ais.helper;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.ipv.core.library.ais.enums.AisInterventionType;
import uk.gov.di.ipv.core.library.dto.AccountInterventionState;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AccountInterventionEvaluatorTest {

    @ParameterizedTest
    @MethodSource("getInvalidAccountInterventionState")
    void shouldReturnTrueWhenProvideInvalidAccountIntervention(
            AisInterventionType aisInterventionType) {
        assertTrue(AccountInterventionEvaluator.hasInvalidAccountIntervention(aisInterventionType));
    }

    private static Stream<Arguments> getInvalidAccountInterventionState() {
        return Stream.of(
                Arguments.of(AisInterventionType.AIS_ACCOUNT_SUSPENDED),
                Arguments.of(AisInterventionType.AIS_ACCOUNT_BLOCKED),
                Arguments.of(AisInterventionType.AIS_FORCED_USER_PASSWORD_RESET),
                Arguments.of(
                        AisInterventionType.AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY));
    }

    @ParameterizedTest
    @MethodSource("getValidAccountInterventionState")
    void shouldReturnFalseWhenProvideValidAccountIntervention(
            AisInterventionType aisInterventionType) {
        assertFalse(
                AccountInterventionEvaluator.hasInvalidAccountIntervention(aisInterventionType));
    }

    private static Stream<Arguments> getValidAccountInterventionState() {
        return Stream.of(
                Arguments.of(AisInterventionType.AIS_NO_INTERVENTION),
                Arguments.of(AisInterventionType.AIS_FORCED_USER_IDENTITY_VERIFY),
                Arguments.of(AisInterventionType.AIS_ACCOUNT_UNBLOCKED),
                Arguments.of(AisInterventionType.AIS_ACCOUNT_UNSUSPENDED));
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
