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

import java.util.Collection;
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
    public void storeIdentity(
            String userId,
            List<VerifiableCredential> credentials,
            String evcsAccessToken,
            boolean isF2FIncomplete)
            throws EvcsServiceException {
        List<EvcsVCState> vcStatesToQueryFor = List.of(CURRENT, PENDING_RETURN);
        List<EvcsGetUserVCDto> existingEvcsUserVCs =
                evcsClient.getUserVcs(userId, evcsAccessToken, vcStatesToQueryFor).vcs();

        persistEvcsUserVCs(userId, credentials, existingEvcsUserVCs, isF2FIncomplete);
    }

    @Tracing
    private void persistEvcsUserVCs(
            String userId,
            List<VerifiableCredential> credentials,
            List<EvcsGetUserVCDto> existingEvcsUserVCs,
            boolean isF2FIncomplete)
            throws EvcsServiceException {
        // AC5 and rest
        List<EvcsCreateUserVCsDto> userVCsForEvcs =
                credentials.stream()
                        .map(
                                vc ->
                                        new EvcsCreateUserVCsDto(
                                                vc.getVcString(),
                                                isF2FIncomplete ? PENDING_RETURN : CURRENT,
                                                null,
                                                null))
                        .toList();

        if (!CollectionUtils.isEmpty(existingEvcsUserVCs)
                && (CollectionUtils.isEmpty(existingEvcsUserVCs) || !isF2FIncomplete)) {
            // AC2 or AC3
            List<EvcsUpdateUserVCsDto> existingCurrentEvcsUserVcsToUpdate =
                    existingEvcsUserVCs.stream()
                            .filter(vc -> vc.state().equals(CURRENT))
                            .map(
                                    vc ->
                                            new EvcsUpdateUserVCsDto(
                                                    vc.vc().split("\\.")[2],
                                                    EvcsVCState.HISTORIC,
                                                    null))
                            .toList();
            // AC4
            List<EvcsUpdateUserVCsDto> existingPendingReturnEvcsUserVcsToUpdate =
                    existingEvcsUserVCs.stream()
                            .filter(vc -> vc.state().equals(PENDING_RETURN))
                            .map(
                                    vc ->
                                            new EvcsUpdateUserVCsDto(
                                                    vc.vc().split("\\.")[2],
                                                    EvcsVCState.ABANDONED,
                                                    null))
                            .toList();
            List<EvcsUpdateUserVCsDto> evcsUserVCsToUpdate =
                    Stream.of(
                                    existingCurrentEvcsUserVcsToUpdate,
                                    existingPendingReturnEvcsUserVcsToUpdate)
                            .flatMap(Collection::stream)
                            .toList();
            evcsClient.updateEvcsUserVCs(userId, evcsUserVCsToUpdate);
        }
        // AC1 and AC5
        evcsClient.createEvcsUserVCs(userId, userVCsForEvcs);
    }
}
