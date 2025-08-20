package uk.gov.di.ipv.core.library.ais.helper;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.support.ParameterDeclarations;
import uk.gov.di.ipv.core.library.dto.AccountInterventionState;

import java.util.stream.Stream;

final class InvalidAccountInterventionArgumentsProvider implements ArgumentsProvider {
    @Override
    public Stream<? extends Arguments> provideArguments(
            ParameterDeclarations parameters, ExtensionContext context) {
        return Stream.of(
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(false)
                                .isReproveIdentity(false)
                                .isResetPassword(true)
                                .build()),
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(false)
                                .isReproveIdentity(true)
                                .isResetPassword(true)
                                .build()),
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(true)
                                .isReproveIdentity(false)
                                .isResetPassword(false)
                                .build()),
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(true)
                                .isReproveIdentity(false)
                                .isResetPassword(true)
                                .build()),
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(false)
                                .isSuspended(true)
                                .isReproveIdentity(true)
                                .isResetPassword(true)
                                .build()),
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(true)
                                .isSuspended(false)
                                .isReproveIdentity(false)
                                .isResetPassword(false)
                                .build()),
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(true)
                                .isSuspended(false)
                                .isReproveIdentity(false)
                                .isResetPassword(true)
                                .build()),
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(true)
                                .isSuspended(false)
                                .isReproveIdentity(true)
                                .isResetPassword(false)
                                .build()),
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(true)
                                .isSuspended(false)
                                .isReproveIdentity(true)
                                .isResetPassword(true)
                                .build()),
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(true)
                                .isSuspended(true)
                                .isReproveIdentity(false)
                                .isResetPassword(false)
                                .build()),
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(true)
                                .isSuspended(true)
                                .isReproveIdentity(false)
                                .isResetPassword(true)
                                .build()),
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(true)
                                .isSuspended(true)
                                .isReproveIdentity(true)
                                .isResetPassword(false)
                                .build()),
                Arguments.of(
                        AccountInterventionState.builder()
                                .isBlocked(true)
                                .isSuspended(true)
                                .isReproveIdentity(true)
                                .isResetPassword(true)
                                .build()));
    }
}
