package uk.gov.di.ipv.core.library.ais.helper;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.ipv.core.library.domain.AisInterventionType;
import uk.gov.di.ipv.core.library.dto.AccountInterventionState;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.ais.TestData.createBlockedIdentityAisState;
import static uk.gov.di.ipv.core.library.ais.TestData.createNoInterventionAisState;
import static uk.gov.di.ipv.core.library.ais.TestData.createReproveIdentityAisState;
import static uk.gov.di.ipv.core.library.ais.TestData.createResetPasswordAisState;
import static uk.gov.di.ipv.core.library.ais.TestData.createSuspendedIdentityAisState;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_ACCOUNT_BLOCKED;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_ACCOUNT_SUSPENDED;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_ACCOUNT_UNBLOCKED;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_ACCOUNT_UNSUSPENDED;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_FORCED_USER_IDENTITY_VERIFY;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_FORCED_USER_PASSWORD_RESET;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_NO_INTERVENTION;

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

    // Equivalent tests to the above but using AIS state
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
    void shouldReturnTrueWhenProvideInvalidMidJourneyAccountInterventionTypes(
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
    void shouldReturnFalseWhenProvideValidMidJourneyAccountInterventionTypes(
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
    void shouldReturnTrueWhenProvideInvalidTicfAccountInterventionTypes(
            AccountInterventionState currentAccountInterventionType,
            AisInterventionType ticfAccountInterventionType) {
        assertTrue(
                AccountInterventionEvaluator.hasTicfIntervention(
                        currentAccountInterventionType, ticfAccountInterventionType));
    }

    private static Stream<Arguments> ticfCodesToTriggerMidJourneyIntervention() {
        return Stream.of(
                Arguments.of(createNoInterventionAisState(), AIS_ACCOUNT_BLOCKED),
                Arguments.of(createNoInterventionAisState(), AIS_ACCOUNT_SUSPENDED),
                Arguments.of(createNoInterventionAisState(), AIS_FORCED_USER_PASSWORD_RESET),
                Arguments.of(createNoInterventionAisState(), AIS_FORCED_USER_IDENTITY_VERIFY),
                Arguments.of(
                        createNoInterventionAisState(),
                        AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY),
                Arguments.of(createReproveIdentityAisState(), AIS_ACCOUNT_BLOCKED),
                Arguments.of(createReproveIdentityAisState(), AIS_ACCOUNT_SUSPENDED),
                Arguments.of(createReproveIdentityAisState(), AIS_FORCED_USER_PASSWORD_RESET),
                Arguments.of(
                        createReproveIdentityAisState(),
                        AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY));
    }

    @ParameterizedTest
    @MethodSource("ticfCodesToNotTriggerMidJourneyIntervention")
    void shouldReturnFalseWhenProvideValidMidJourneyAccountInterventionTypes(
            AccountInterventionState currentAccountInterventionType,
            AisInterventionType ticfAccountInterventionType) {
        assertFalse(
                AccountInterventionEvaluator.hasTicfIntervention(
                        currentAccountInterventionType, ticfAccountInterventionType));
    }

    private static Stream<Arguments> ticfCodesToNotTriggerMidJourneyIntervention() {
        return Stream.of(
                Arguments.of(createNoInterventionAisState(), AIS_NO_INTERVENTION),
                Arguments.of(createNoInterventionAisState(), AIS_ACCOUNT_UNSUSPENDED),
                Arguments.of(createNoInterventionAisState(), AIS_ACCOUNT_UNBLOCKED),
                Arguments.of(createReproveIdentityAisState(), AIS_FORCED_USER_IDENTITY_VERIFY),
                Arguments.of(createReproveIdentityAisState(), AIS_ACCOUNT_UNBLOCKED),
                Arguments.of(createReproveIdentityAisState(), AIS_ACCOUNT_UNSUSPENDED),
                Arguments.of(createReproveIdentityAisState(), AIS_NO_INTERVENTION));
    }
}
