package uk.gov.di.ipv.core.library.ais.helper;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.support.ParameterDeclarations;
import uk.gov.di.ipv.core.library.dto.AccountInterventionState;

import java.util.stream.Stream;

public class InvalidMidJourneyAccountInterventionArgumentsProvider implements ArgumentsProvider {
    @Override
    public Stream<? extends Arguments> provideArguments(
            ParameterDeclarations parameters, ExtensionContext context) throws Exception {
        return Stream.of(
                // Initially just reprove
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(false)
                                .isReproveIdentity(true)
                                .isResetPassword(false)
                                .build(),
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(false)
                                .isReproveIdentity(false)
                                .isResetPassword(false)
                                .build()),
                // Finally blocked
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(false)
                                .isReproveIdentity(false)
                                .isResetPassword(false)
                                .build(),
                        AccountInterventionState.builder()
                                .isBlocked(true)
                                .isSuspended(false)
                                .isReproveIdentity(false)
                                .isResetPassword(false)
                                .build()),
                // Finally just suspended
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(false)
                                .isReproveIdentity(false)
                                .isResetPassword(false)
                                .build(),
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(true)
                                .isReproveIdentity(false)
                                .isResetPassword(false)
                                .build()),
                // Finally just reprove
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(false)
                                .isReproveIdentity(false)
                                .isResetPassword(false)
                                .build(),
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(false)
                                .isReproveIdentity(true)
                                .isResetPassword(false)
                                .build()),
                // Finally reset password
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(false)
                                .isReproveIdentity(false)
                                .isResetPassword(false)
                                .build(),
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(false)
                                .isReproveIdentity(false)
                                .isResetPassword(true)
                                .build()),
                // Reprove identity that has been triggered during the journey
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(false)
                                .isReproveIdentity(false)
                                .isResetPassword(false)
                                .build(),
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(true)
                                .isReproveIdentity(true)
                                .isResetPassword(false)
                                .build()),
                // Reprove identity that cleared during the journey but got re-suspended
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(true)
                                .isReproveIdentity(true)
                                .isResetPassword(false)
                                .build(),
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(true)
                                .isReproveIdentity(false)
                                .isResetPassword(false)
                                .build()),
                // Reprove identity that cleared during the journey but got blocked during the
                // journey
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(true)
                                .isReproveIdentity(true)
                                .isResetPassword(false)
                                .build(),
                        AccountInterventionState.builder()
                                .isBlocked(true)
                                .isSuspended(false)
                                .isReproveIdentity(false)
                                .isResetPassword(false)
                                .build()));
    }
}
