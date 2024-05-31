package uk.gov.di.ipv.core.library.service;

import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.client.EvcsClient;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.dto.EvcsGetUserVCDto;
import uk.gov.di.ipv.core.library.dto.EvcsUpdateUserVCsDto;
import uk.gov.di.ipv.core.library.enums.EvcsVCState;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;

import java.util.List;
import java.util.stream.Stream;

import static uk.gov.di.ipv.core.library.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.PENDING_RETURN;

public class EvcsService {
    private final EvcsClient evcsClient;

    @ExcludeFromGeneratedCoverageReport
    public EvcsService(ConfigService configService) {
        this.evcsClient = new EvcsClient(configService);
    }

    public EvcsService(EvcsClient evcsClient) {
        this.evcsClient = evcsClient;
    }

    @Tracing
    public void storeCompletedIdentity(
            String userId, List<VerifiableCredential> credentials, String evcsAccessToken)
            throws EvcsServiceException {
        List<EvcsGetUserVCDto> existingEvcsUserVCs =
                evcsClient
                        .getUserVcs(userId, evcsAccessToken, List.of(CURRENT, PENDING_RETURN))
                        .vcs();

        persistEvcsUserVCs(userId, credentials, existingEvcsUserVCs, false);
    }

    @Tracing
    public void storePendingIdentity(
            String userId, List<VerifiableCredential> credentials, String evcsAccessToken)
            throws EvcsServiceException {
        List<EvcsGetUserVCDto> existingEvcsUserVCs =
                evcsClient
                        .getUserVcs(userId, evcsAccessToken, List.of(CURRENT, PENDING_RETURN))
                        .vcs();

        persistEvcsUserVCs(userId, credentials, existingEvcsUserVCs, true);
    }

    @Tracing
    private void persistEvcsUserVCs(
            String userId,
            List<VerifiableCredential> credentials,
            List<EvcsGetUserVCDto> existingEvcsUserVCs,
            boolean isPendingIdentity)
            throws EvcsServiceException {
        List<EvcsCreateUserVCsDto> userVCsForEvcs =
                credentials.stream()
                        .filter(
                                credential ->
                                        existingEvcsUserVCs.stream()
                                                .noneMatch(
                                                        evcsVC ->
                                                                evcsVC.vc()
                                                                        .equals(
                                                                                credential
                                                                                        .getVcString())))
                        .map(
                                vc ->
                                        new EvcsCreateUserVCsDto(
                                                vc.getVcString(),
                                                isPendingIdentity ? PENDING_RETURN : CURRENT,
                                                null,
                                                null))
                        .toList();

        if (!CollectionUtils.isEmpty(existingEvcsUserVCs) && !isPendingIdentity) {
            var existingCurrentEvcsUserVcsToUpdate =
                    existingEvcsUserVCs.stream()
                            .filter(vc -> vc.state().equals(CURRENT))
                            .filter(
                                    vc ->
                                            credentials.stream()
                                                    .noneMatch(
                                                            credential ->
                                                                    credential
                                                                            .getVcString()
                                                                            .equals(vc.vc())))
                            .map(
                                    vc ->
                                            new EvcsUpdateUserVCsDto(
                                                    getVcSignature(vc), EvcsVCState.HISTORIC, null))
                            .toList();
            var existingPendingReturnEvcsUserVcsToUpdate =
                    existingEvcsUserVCs.stream()
                            .filter(vc -> vc.state().equals(PENDING_RETURN))
                            .map(
                                    vc ->
                                            new EvcsUpdateUserVCsDto(
                                                    getVcSignature(vc),
                                                    EvcsVCState.ABANDONED,
                                                    null))
                            .toList();
            var evcsUserVCsToUpdate =
                    Stream.concat(
                                    existingCurrentEvcsUserVcsToUpdate.stream(),
                                    existingPendingReturnEvcsUserVcsToUpdate.stream())
                            .toList();

            evcsClient.updateUserVCs(userId, evcsUserVCsToUpdate);
        }
        evcsClient.storeUserVCs(userId, userVCsForEvcs);
    }

    private static String getVcSignature(EvcsGetUserVCDto vc) {
        return vc.vc().split("\\.")[2];
    }
}
