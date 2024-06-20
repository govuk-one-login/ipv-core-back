package uk.gov.di.ipv.core.library.service;

import com.nimbusds.jwt.SignedJWT;
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
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.NoCriForIssuerException;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import static uk.gov.di.ipv.core.library.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.PENDING_RETURN;

public class EvcsService {
    private final EvcsClient evcsClient;
    private final ConfigService configService;

    @ExcludeFromGeneratedCoverageReport
    public EvcsService(EvcsClient evcsClient, ConfigService configService) {
        this.evcsClient = evcsClient;
        this.configService = configService;
    }

    @ExcludeFromGeneratedCoverageReport
    public EvcsService(ConfigService configService) {
        this.evcsClient = new EvcsClient(configService);
        this.configService = configService;
    }

    @Tracing
    public void storeCompletedIdentity(
            String userId, List<VerifiableCredential> credentials, String evcsAccessToken)
            throws EvcsServiceException {
        persistEvcsUserVCs(
                userId,
                credentials,
                getEvcsGetUserVCDtos(userId, evcsAccessToken, CURRENT, PENDING_RETURN),
                false);
    }

    @Tracing
    public void storePendingIdentity(
            String userId, List<VerifiableCredential> credentials, String evcsAccessToken)
            throws EvcsServiceException {
        persistEvcsUserVCs(
                userId,
                credentials,
                getEvcsGetUserVCDtos(userId, evcsAccessToken, CURRENT, PENDING_RETURN),
                true);
    }

    @Tracing
    public List<VerifiableCredential> getVerifiableCredentials(
            String userId, String evcsAccessToken, EvcsVCState... states)
            throws CredentialParseException, EvcsServiceException {
        List<EvcsGetUserVCDto> vcs = getEvcsGetUserVCDtos(userId, evcsAccessToken, states);

        List<VerifiableCredential> credentials = new ArrayList<>();
        for (var vc : vcs) {
            try {
                var jwt = SignedJWT.parse(vc.vc());
                var cri = configService.getCriByIssuer(jwt.getJWTClaimsSet().getIssuer());
                credentials.add(VerifiableCredential.fromValidJwt(userId, cri.getId(), jwt));
            } catch (NoCriForIssuerException e) {
                throw new CredentialParseException("Failed to find credential issuer for vc", e);
            } catch (ParseException e) {
                throw new CredentialParseException(
                        "Encountered a parsing error while attempting to parse evcs credentials",
                        e);
            }
        }
        return credentials;
    }

    @Tracing
    public void storePendingVc(VerifiableCredential credential) throws EvcsServiceException {
        evcsClient.storeUserVCs(
                credential.getUserId(),
                List.of(
                        new EvcsCreateUserVCsDto(
                                credential.getVcString(), PENDING_RETURN, null, null)));
    }

    @Tracing
    private List<EvcsGetUserVCDto> getEvcsGetUserVCDtos(
            String userId, String evcsAccessToken, EvcsVCState... states)
            throws EvcsServiceException {
        List<EvcsGetUserVCDto> existingEvcsUserVCs =
                evcsClient.getUserVcs(userId, evcsAccessToken, List.of(states)).vcs();
        return existingEvcsUserVCs;
    }

    @Tracing
    private void persistEvcsUserVCs(
            String userId,
            List<VerifiableCredential> credentials,
            List<EvcsGetUserVCDto> existingEvcsUserVCs,
            boolean isPendingIdentity)
            throws EvcsServiceException {
        List<EvcsCreateUserVCsDto> userVCsToStore =
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

        if (!CollectionUtils.isEmpty(existingEvcsUserVCs))
            updateExistingUserVCs(userId, credentials, existingEvcsUserVCs, isPendingIdentity);
        if (!userVCsToStore.isEmpty()) evcsClient.storeUserVCs(userId, userVCsToStore);
    }

    @Tracing
    private void updateExistingUserVCs(
            String userId,
            List<VerifiableCredential> credentials,
            List<EvcsGetUserVCDto> existingEvcsUserVCs,
            boolean isPendingIdentity)
            throws EvcsServiceException {
        var vcsToUpdates = new ArrayList<EvcsUpdateUserVCsDto>();
        var existingPendingReturnUserVcsNotInSessionToUpdate =
                existingEvcsUserVCs.stream()
                        .filter(vc -> vc.state().equals(PENDING_RETURN))
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
                                                getVcSignature(vc), EvcsVCState.ABANDONED, null))
                        .toList();
        vcsToUpdates.addAll(existingPendingReturnUserVcsNotInSessionToUpdate);

        if (!isPendingIdentity) {
            var existingPendingReturnUserVcsInSessionToUpdate =
                    existingEvcsUserVCs.stream()
                            .filter(vc -> vc.state().equals(PENDING_RETURN))
                            .filter(
                                    vc ->
                                            credentials.stream()
                                                    .anyMatch(
                                                            credential ->
                                                                    credential
                                                                            .getVcString()
                                                                            .equals(vc.vc())))
                            .map(
                                    vc ->
                                            new EvcsUpdateUserVCsDto(
                                                    getVcSignature(vc), EvcsVCState.CURRENT, null))
                            .toList();
            vcsToUpdates.addAll(existingPendingReturnUserVcsInSessionToUpdate);

            var existingCurrentUserVcsNotInSessionToUpdate =
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
            vcsToUpdates.addAll(existingCurrentUserVcsNotInSessionToUpdate);
        }

        if (!vcsToUpdates.isEmpty()) evcsClient.updateUserVCs(userId, vcsToUpdates);
    }

    private static String getVcSignature(EvcsGetUserVCDto vc) {
        return vc.vc().split("\\.")[2];
    }
}
