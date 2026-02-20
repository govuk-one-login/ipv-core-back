package uk.gov.di.ipv.core.library.ais.helper;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.ipv.core.library.dto.AccountInterventionState;
import uk.gov.di.ipv.core.library.enums.TicfCode;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.ais.TestData.createBlockedIdentityAisState;
import static uk.gov.di.ipv.core.library.ais.TestData.createNoInterventionAisState;
import static uk.gov.di.ipv.core.library.ais.TestData.createReproveIdentityAisState;
import static uk.gov.di.ipv.core.library.ais.TestData.createResetPasswordAisState;
import static uk.gov.di.ipv.core.library.ais.TestData.createSuspendedIdentityAisState;
import static uk.gov.di.ipv.core.library.enums.TicfCode.ACCOUNT_BLOCKED;
import static uk.gov.di.ipv.core.library.enums.TicfCode.ACCOUNT_SUSPENDED;
import static uk.gov.di.ipv.core.library.enums.TicfCode.ACCOUNT_UNBLOCKED;
import static uk.gov.di.ipv.core.library.enums.TicfCode.ACCOUNT_UNSUSPENDED;
import static uk.gov.di.ipv.core.library.enums.TicfCode.FORCED_USER_IDENTITY_VERIFY;
import static uk.gov.di.ipv.core.library.enums.TicfCode.FORCED_USER_PASSWORD_RESET;
import static uk.gov.di.ipv.core.library.enums.TicfCode.FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY;
import static uk.gov.di.ipv.core.library.enums.TicfCode.NO_INTERVENTION;

class AccountInterventionEvaluatorTest {

    @ParameterizedTest
    @MethodSource("aisStatesToTriggerStartOfJourneyIntervention")
    void shouldReturnTrueWhenProvideInvalidAccountState(AccountInterventionState aisState) {
        assertTrue(AccountInterventionEvaluator.hasStartOfJourneyIntervention(aisState));
    }

    private static Stream<Arguments> aisStatesToTriggerStartOfJourneyIntervention() {
        return Stream.of(
                Arguments.of(createSuspendedIdentityAisState()),
                Arguments.of(createBlockedIdentityAisState()),
                Arguments.of(createResetPasswordAisState()));
    }

    @ParameterizedTest
    @MethodSource("aisStatesToNotTriggerStartOfJourneyIntervention")
    void shouldReturnFalseWhenProvideValidAccountState(AccountInterventionState aisState) {
        assertFalse(AccountInterventionEvaluator.hasStartOfJourneyIntervention(aisState));
    }

    private static Stream<Arguments> aisStatesToNotTriggerStartOfJourneyIntervention() {
        return Stream.of(
                Arguments.of(createNoInterventionAisState()),
                Arguments.of(createReproveIdentityAisState()));
    }

    @ParameterizedTest
    @MethodSource("aisStatesToTriggerMidJourneyIntervention")
    void shouldReturnTrueWhenProvideInvalidMidJourneyAccountInterventionState(
            boolean isReproveJourney, AccountInterventionState finalAisInterventionType) {
        assertTrue(
                AccountInterventionEvaluator.hasMidJourneyIntervention(
                        isReproveJourney, finalAisInterventionType));
    }

    private static Stream<Arguments> aisStatesToTriggerMidJourneyIntervention() {
        return Stream.of(
                Arguments.of(false, createBlockedIdentityAisState()),
                Arguments.of(false, createSuspendedIdentityAisState()),
                Arguments.of(false, createReproveIdentityAisState()),
                Arguments.of(false, createResetPasswordAisState()),
                Arguments.of(true, createBlockedIdentityAisState()),
                Arguments.of(true, createSuspendedIdentityAisState()),
                Arguments.of(true, createResetPasswordAisState()));
    }

    @ParameterizedTest
    @MethodSource("aisStatesToNotTriggerMidJourneyIntervention")
    void shouldReturnFalseWhenProvideValidMidJourneyAccountInterventionState(
            boolean isReproveIdentity, AccountInterventionState finalAisInterventionType) {
        assertFalse(
                AccountInterventionEvaluator.hasMidJourneyIntervention(
                        isReproveIdentity, finalAisInterventionType));
    }

    private static Stream<Arguments> aisStatesToNotTriggerMidJourneyIntervention() {
        return Stream.of(
                Arguments.of(false, createNoInterventionAisState()),
                Arguments.of(true, createReproveIdentityAisState()),
                Arguments.of(true, createNoInterventionAisState()));
    }

    @ParameterizedTest
    @MethodSource("ticfCodesToTriggerMidJourneyIntervention")
    void shouldReturnTrueWhenProvideInvalidMidJourneyTicfCode(
            AccountInterventionState currentAccountInterventionType,
            TicfCode ticfAccountInterventionType) {
        assertTrue(
                AccountInterventionEvaluator.hasTicfIntervention(
                        currentAccountInterventionType, ticfAccountInterventionType));
    }

    private static Stream<Arguments> ticfCodesToTriggerMidJourneyIntervention() {
        return Stream.of(
                Arguments.of(createNoInterventionAisState(), ACCOUNT_BLOCKED),
                Arguments.of(createNoInterventionAisState(), ACCOUNT_SUSPENDED),
                Arguments.of(createNoInterventionAisState(), FORCED_USER_PASSWORD_RESET),
                Arguments.of(createNoInterventionAisState(), FORCED_USER_IDENTITY_VERIFY),
                Arguments.of(
                        createNoInterventionAisState(),
                        FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY),
                Arguments.of(createReproveIdentityAisState(), ACCOUNT_BLOCKED),
                Arguments.of(createReproveIdentityAisState(), ACCOUNT_SUSPENDED),
                Arguments.of(createReproveIdentityAisState(), FORCED_USER_PASSWORD_RESET),
                Arguments.of(
                        createReproveIdentityAisState(),
                        FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY));
    }

    @ParameterizedTest
    @MethodSource("ticfCodesToNotTriggerMidJourneyIntervention")
    void shouldReturnFalseWhenProvideValidMidJourneyTicfCode(
            AccountInterventionState currentAccountInterventionType,
            TicfCode ticfAccountInterventionType) {
        assertFalse(
                AccountInterventionEvaluator.hasTicfIntervention(
                        currentAccountInterventionType, ticfAccountInterventionType));
    }

    private static Stream<Arguments> ticfCodesToNotTriggerMidJourneyIntervention() {
        return Stream.of(
                Arguments.of(createNoInterventionAisState(), NO_INTERVENTION),
                Arguments.of(createNoInterventionAisState(), ACCOUNT_UNSUSPENDED),
                Arguments.of(createNoInterventionAisState(), ACCOUNT_UNBLOCKED),
                Arguments.of(createReproveIdentityAisState(), FORCED_USER_IDENTITY_VERIFY),
                Arguments.of(createReproveIdentityAisState(), ACCOUNT_UNBLOCKED),
                Arguments.of(createReproveIdentityAisState(), ACCOUNT_UNSUSPENDED),
                Arguments.of(createReproveIdentityAisState(), NO_INTERVENTION));
    }
}
