package uk.gov.di.ipv.core.library.ais.helper;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.ipv.core.library.domain.AisInterventionType;
import uk.gov.di.ipv.core.library.dto.AccountInterventionState;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.*;

class AccountInterventionEvaluatorTest {

    @ParameterizedTest
    @MethodSource("getInvalidAccountInterventionState")
    void shouldReturnTrueWhenProvideInvalidAccountIntervention(
            AisInterventionType aisInterventionType) {
        assertTrue(AccountInterventionEvaluator.hasInvalidAccountIntervention(aisInterventionType));
    }

    private static Stream<Arguments> getInvalidAccountInterventionState() {
        return Stream.of(
                Arguments.of(AIS_ACCOUNT_SUSPENDED),
                Arguments.of(AIS_ACCOUNT_BLOCKED),
                Arguments.of(AIS_FORCED_USER_PASSWORD_RESET),
                Arguments.of(AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY));
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
                Arguments.of(AIS_NO_INTERVENTION),
                Arguments.of(AIS_FORCED_USER_IDENTITY_VERIFY),
                Arguments.of(AIS_ACCOUNT_UNBLOCKED),
                Arguments.of(AIS_ACCOUNT_UNSUSPENDED));
    }

    @ParameterizedTest
    @ArgumentsSource(InvalidMidJourneyAccountInterventionArgumentsProvider.class)
    void shouldReturnTrueWhenProvideValidMidJourneyAccountInterventionStates(
            AccountInterventionState initialAccountIntervention,
            AccountInterventionState midJourneyAccountInterventionState) {
        assertTrue(
                AccountInterventionEvaluator.isMidJourneyInterventionDetected(
                        initialAccountIntervention, midJourneyAccountInterventionState));
    }

    @ParameterizedTest
    @MethodSource("getInvalidMidJourneyAccountInterventionTypes")
    void shouldReturnTrueWhenProvideInvalidMidJourneyAccountInterventionTypes(
            AisInterventionType initialAisInterventionType,
            AisInterventionType finalAisInterventionType) {
        assertTrue(
                AccountInterventionEvaluator.isMidJourneyInterventionDetected(
                        initialAisInterventionType, finalAisInterventionType));
    }

    private static Stream<Arguments> getInvalidMidJourneyAccountInterventionTypes() {
        return Stream.of(
                Arguments.of(AIS_NO_INTERVENTION, AIS_ACCOUNT_BLOCKED),
                Arguments.of(AIS_NO_INTERVENTION, AIS_ACCOUNT_SUSPENDED),
                Arguments.of(AIS_NO_INTERVENTION, AIS_FORCED_USER_PASSWORD_RESET),
                Arguments.of(AIS_NO_INTERVENTION, AIS_FORCED_USER_IDENTITY_VERIFY),
                Arguments.of(
                        AIS_NO_INTERVENTION, AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY),
                Arguments.of(AIS_ACCOUNT_UNBLOCKED, AIS_ACCOUNT_BLOCKED),
                Arguments.of(AIS_ACCOUNT_UNBLOCKED, AIS_ACCOUNT_SUSPENDED),
                Arguments.of(AIS_ACCOUNT_UNBLOCKED, AIS_FORCED_USER_PASSWORD_RESET),
                Arguments.of(AIS_ACCOUNT_UNBLOCKED, AIS_FORCED_USER_IDENTITY_VERIFY),
                Arguments.of(
                        AIS_ACCOUNT_UNBLOCKED, AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY),
                Arguments.of(AIS_ACCOUNT_UNSUSPENDED, AIS_ACCOUNT_BLOCKED),
                Arguments.of(AIS_ACCOUNT_UNSUSPENDED, AIS_ACCOUNT_SUSPENDED),
                Arguments.of(AIS_ACCOUNT_UNSUSPENDED, AIS_FORCED_USER_PASSWORD_RESET),
                Arguments.of(AIS_ACCOUNT_UNSUSPENDED, AIS_FORCED_USER_IDENTITY_VERIFY),
                Arguments.of(
                        AIS_ACCOUNT_UNSUSPENDED,
                        AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY),
                Arguments.of(AIS_FORCED_USER_IDENTITY_VERIFY, AIS_ACCOUNT_BLOCKED),
                Arguments.of(AIS_FORCED_USER_IDENTITY_VERIFY, AIS_ACCOUNT_SUSPENDED),
                Arguments.of(AIS_FORCED_USER_IDENTITY_VERIFY, AIS_FORCED_USER_PASSWORD_RESET),
                Arguments.of(
                        AIS_FORCED_USER_IDENTITY_VERIFY,
                        AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY));
    }

    @ParameterizedTest
    @MethodSource("getValidMidJourneyAccountInterventionTypes")
    void shouldReturnFalseWhenProvideValidMidJourneyAccountInterventionTypes(
            AisInterventionType initialAisInterventionType,
            AisInterventionType finalAisInterventionType) {
        assertFalse(
                AccountInterventionEvaluator.isMidJourneyInterventionDetected(
                        initialAisInterventionType, finalAisInterventionType));
    }

    private static Stream<Arguments> getValidMidJourneyAccountInterventionTypes() {
        return Stream.of(
                Arguments.of(AIS_NO_INTERVENTION, AIS_NO_INTERVENTION),
                Arguments.of(AIS_NO_INTERVENTION, AIS_ACCOUNT_UNSUSPENDED),
                Arguments.of(AIS_NO_INTERVENTION, AIS_ACCOUNT_UNBLOCKED),
                Arguments.of(AIS_ACCOUNT_UNBLOCKED, AIS_ACCOUNT_UNBLOCKED),
                Arguments.of(AIS_ACCOUNT_UNBLOCKED, AIS_NO_INTERVENTION),
                Arguments.of(AIS_ACCOUNT_UNBLOCKED, AIS_ACCOUNT_UNSUSPENDED),
                Arguments.of(AIS_ACCOUNT_UNSUSPENDED, AIS_ACCOUNT_UNSUSPENDED),
                Arguments.of(AIS_ACCOUNT_UNSUSPENDED, AIS_NO_INTERVENTION),
                Arguments.of(AIS_ACCOUNT_UNSUSPENDED, AIS_ACCOUNT_UNBLOCKED),
                Arguments.of(AIS_FORCED_USER_IDENTITY_VERIFY, AIS_FORCED_USER_IDENTITY_VERIFY),
                Arguments.of(AIS_FORCED_USER_IDENTITY_VERIFY, AIS_ACCOUNT_UNBLOCKED),
                Arguments.of(AIS_FORCED_USER_IDENTITY_VERIFY, AIS_ACCOUNT_UNSUSPENDED),
                Arguments.of(AIS_FORCED_USER_IDENTITY_VERIFY, AIS_NO_INTERVENTION));
    }
}
