package uk.gov.di.ipv.core.library.ais.helper;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.ipv.core.library.domain.AisInterventionType;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.*;

class AccountInterventionEvaluatorTest {

    @ParameterizedTest
    @MethodSource("getInvalidAccountInterventionState")
    void shouldReturnTrueWhenProvideInvalidAccountIntervention(
            AisInterventionType aisInterventionType) {
        assertTrue(AccountInterventionEvaluator.hasStartOfJourneyIntervention(aisInterventionType));
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
                AccountInterventionEvaluator.hasStartOfJourneyIntervention(aisInterventionType));
    }

    private static Stream<Arguments> getValidAccountInterventionState() {
        return Stream.of(
                Arguments.of(AIS_NO_INTERVENTION),
                Arguments.of(AIS_FORCED_USER_IDENTITY_VERIFY),
                Arguments.of(AIS_ACCOUNT_UNBLOCKED),
                Arguments.of(AIS_ACCOUNT_UNSUSPENDED));
    }

    @ParameterizedTest
    @MethodSource("getInvalidMidJourneyAccountInterventionTypes")
    void shouldReturnTrueWhenProvideInvalidMidJourneyAccountInterventionTypes(
            boolean isReproveJourney, AisInterventionType finalAisInterventionType) {
        assertTrue(
                AccountInterventionEvaluator.hasMidJourneyIntervention(
                        isReproveJourney, finalAisInterventionType));
    }

    private static Stream<Arguments> getInvalidMidJourneyAccountInterventionTypes() {
        return Stream.of(
                Arguments.of(false, AIS_ACCOUNT_BLOCKED),
                Arguments.of(false, AIS_ACCOUNT_SUSPENDED),
                Arguments.of(false, AIS_FORCED_USER_IDENTITY_VERIFY),
                Arguments.of(false, AIS_FORCED_USER_PASSWORD_RESET),
                Arguments.of(false, AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY),
                Arguments.of(true, AIS_ACCOUNT_BLOCKED),
                Arguments.of(true, AIS_ACCOUNT_SUSPENDED),
                Arguments.of(true, AIS_FORCED_USER_PASSWORD_RESET),
                Arguments.of(true, AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY));
    }

    @ParameterizedTest
    @MethodSource("getValidMidJourneyAccountInterventionTypes")
    void shouldReturnFalseWhenProvideValidMidJourneyAccountInterventionTypes(
            boolean isReproveIdentity, AisInterventionType finalAisInterventionType) {
        assertFalse(
                AccountInterventionEvaluator.hasMidJourneyIntervention(
                        isReproveIdentity, finalAisInterventionType));
    }

    private static Stream<Arguments> getValidMidJourneyAccountInterventionTypes() {
        return Stream.of(
                Arguments.of(false, AIS_NO_INTERVENTION),
                Arguments.of(false, AIS_ACCOUNT_UNSUSPENDED),
                Arguments.of(true, AIS_FORCED_USER_IDENTITY_VERIFY),
                Arguments.of(true, AIS_ACCOUNT_UNBLOCKED),
                Arguments.of(true, AIS_ACCOUNT_UNSUSPENDED),
                Arguments.of(true, AIS_NO_INTERVENTION));
    }

    @ParameterizedTest
    @MethodSource("getInvalidTicfAccountInterventionTypes")
    void shouldReturnTrueWhenProvideInvalidTicfAccountInterventionTypes(
            AisInterventionType currentAccountInterventionType,
            AisInterventionType ticfAccountInterventionType) {
        assertTrue(
                AccountInterventionEvaluator.hasTicfIntervention(
                        currentAccountInterventionType, ticfAccountInterventionType));
    }

    private static Stream<Arguments> getInvalidTicfAccountInterventionTypes() {
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
    @MethodSource("getValidTicfAccountInterventionTypes")
    void shouldReturnFalseWhenProvideValidMidJourneyAccountInterventionTypes(
            AisInterventionType currentAccountInterventionType,
            AisInterventionType ticfAccountInterventionType) {
        assertFalse(
                AccountInterventionEvaluator.hasTicfIntervention(
                        currentAccountInterventionType, ticfAccountInterventionType));
    }

    private static Stream<Arguments> getValidTicfAccountInterventionTypes() {
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
