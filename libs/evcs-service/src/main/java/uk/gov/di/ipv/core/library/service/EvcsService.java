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
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.enums.EvcsVCState.ABANDONED;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.HISTORIC;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.enums.EvcsVcProvenance.EXTERNAL;
import static uk.gov.di.ipv.core.library.enums.EvcsVcProvenance.OFFLINE;
import static uk.gov.di.ipv.core.library.enums.EvcsVcProvenance.ONLINE;

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
        persistUserVCs(
                userId,
                credentials,
                getUserVCs(userId, evcsAccessToken, CURRENT, PENDING_RETURN),
                false);
    }

    @Tracing
    public void storePendingIdentity(
            String userId, List<VerifiableCredential> credentials, String evcsAccessToken)
            throws EvcsServiceException {
        persistUserVCs(
                userId,
                credentials,
                getUserVCs(userId, evcsAccessToken, CURRENT, PENDING_RETURN),
                true);
    }

    @Tracing
    public void storeMigratedIdentity(String userId, List<VerifiableCredential> credentials)
            throws EvcsServiceException {
        // If we are migrating, assume that there is no existing identity to mark as historic
        evcsClient.storeUserVCs(
                userId,
                credentials.stream()
                        .map(
                                vc ->
                                        new EvcsCreateUserVCsDto(
                                                vc.getVcString(), CURRENT, null, ONLINE))
                        .toList());
    }

    @Tracing
    public void storeInheritedIdentity(
            String userId,
            VerifiableCredential incomingInheritedIdentity,
            VerifiableCredential existingInheritedIdentity)
            throws EvcsServiceException {
        if (existingInheritedIdentity != null) {
            evcsClient.updateUserVCs(
                    userId,
                    List.of(
                            new EvcsUpdateUserVCsDto(
                                    getVcSignature(existingInheritedIdentity.getVcString()),
                                    HISTORIC,
                                    null)));
        }
        evcsClient.storeUserVCs(
                userId,
                List.of(
                        new EvcsCreateUserVCsDto(
                                incomingInheritedIdentity.getVcString(), CURRENT, null, EXTERNAL)));
    }

    @Tracing
    public List<VerifiableCredential> getVerifiableCredentials(
            String userId, String evcsAccessToken, EvcsVCState... states)
            throws CredentialParseException, EvcsServiceException {
        return getVerifiableCredentialsByState(userId, evcsAccessToken, states).values().stream()
                .flatMap(List::stream)
                .toList();
    }

    @Tracing
    public Map<EvcsVCState, List<VerifiableCredential>> getVerifiableCredentialsByState(
            String userId, String evcsAccessToken, EvcsVCState... states)
            throws CredentialParseException, EvcsServiceException {
        Map<EvcsVCState, List<VerifiableCredential>> credentials = new EnumMap<>(EvcsVCState.class);
        for (var vc : getUserVCs(userId, evcsAccessToken, states)) {
            try {
                var jwt = SignedJWT.parse(vc.vc());
                var cri = configService.getCriByIssuer(jwt.getJWTClaimsSet().getIssuer());
                var credential = VerifiableCredential.fromValidJwt(userId, cri, jwt);
                if (!credentials.containsKey(vc.state())) {
                    credentials.put(vc.state(), new ArrayList<>());
                }
                credentials.get(vc.state()).add(credential);
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
                                credential.getVcString(), PENDING_RETURN, null, OFFLINE)));
    }

    public void abandonPendingIdentity(String userId, String evcsAccessToken)
            throws EvcsServiceException {
        List<EvcsUpdateUserVCsDto> vcsToUpdates =
                getUserVCs(userId, evcsAccessToken, PENDING_RETURN).stream()
                        .map(
                                vc ->
                                        new EvcsUpdateUserVCsDto(
                                                getVcSignature(vc.vc()), ABANDONED, null))
                        .toList();
        if (!vcsToUpdates.isEmpty()) evcsClient.updateUserVCs(userId, vcsToUpdates);
    }

    private List<EvcsGetUserVCDto> getUserVCs(
            String userId, String evcsAccessToken, EvcsVCState... states)
            throws EvcsServiceException {
        return evcsClient.getUserVcs(userId, evcsAccessToken, List.of(states)).vcs();
    }

    private void persistUserVCs(
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
                                                ONLINE))
                        .toList();

        if (!CollectionUtils.isEmpty(existingEvcsUserVCs))
            updateExistingUserVCs(userId, credentials, existingEvcsUserVCs, isPendingIdentity);
        if (!userVCsToStore.isEmpty()) evcsClient.storeUserVCs(userId, userVCsToStore);
    }

    private void updateExistingUserVCs(
            String userId,
            List<VerifiableCredential> credentials,
            List<EvcsGetUserVCDto> existingEvcsUserVCs,
            boolean isPendingIdentity)
            throws EvcsServiceException {
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
                                                getVcSignature(vc.vc()),
                                                EvcsVCState.ABANDONED,
                                                null))
                        .toList();
        var vcsToUpdates = new ArrayList<>(existingPendingReturnUserVcsNotInSessionToUpdate);

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
                                                    getVcSignature(vc.vc()),
                                                    EvcsVCState.CURRENT,
                                                    null))
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
                                                    getVcSignature(vc.vc()),
                                                    EvcsVCState.HISTORIC,
                                                    null))
                            .toList();
            vcsToUpdates.addAll(existingCurrentUserVcsNotInSessionToUpdate);
        }

        if (!vcsToUpdates.isEmpty()) evcsClient.updateUserVCs(userId, vcsToUpdates);
    }

    private static String getVcSignature(String vcString) {
        return vcString.split("\\.")[2];
    }
}
