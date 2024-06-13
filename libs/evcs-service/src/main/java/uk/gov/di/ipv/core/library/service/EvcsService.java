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

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

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
    public List<VerifiableCredential> getVerifiableCredentials(
            String userId, String evcsAccessToken, EvcsVCState... states)
            throws CredentialParseException {
        List<EvcsGetUserVCDto> vcs =
                evcsClient.getUserVcs(userId, evcsAccessToken, List.of(states)).vcs();

        var criConfig = configService.getCriConfigs();

        List<VerifiableCredential> credentials = new ArrayList<>();
        for (var vc : vcs) {
            try {
                var jwt = SignedJWT.parse(vc.vc());
                var criId = criConfig.get(jwt.getJWTClaimsSet().getIssuer());
                if (criId == null) {
                    throw new CredentialParseException(
                            "Failed to find credential issuer for vc "
                                    + jwt.getJWTClaimsSet().getIssuer());
                }
                credentials.add(VerifiableCredential.fromValidJwt(userId, criId, jwt));
            } catch (ParseException e) {
                throw new CredentialParseException(
                        "Encountered a parsing error while attempting to parse evcs credentials",
                        e);
            }
        }
        return credentials;
    }

    @Tracing
    public void storePendingVc(VerifiableCredential credential) {
        evcsClient.storeUserVCs(
                credential.getUserId(),
                List.of(
                        new EvcsCreateUserVCsDto(
                                credential.getVcString(), PENDING_RETURN, null, null)));
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
