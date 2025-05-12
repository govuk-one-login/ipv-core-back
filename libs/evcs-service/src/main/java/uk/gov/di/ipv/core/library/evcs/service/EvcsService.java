package uk.gov.di.ipv.core.library.evcs.service;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.client.EvcsClient;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsGetUserVCDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsPutUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsStoredIdentityDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsUpdateUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.exception.FailedToCreateStoredIdentityForEvcsException;
import uk.gov.di.ipv.core.library.evcs.metadata.InheritedIdentityMetadata;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.NoCriForIssuerException;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.STORED_IDENTITY_SERVICE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_CREATE_STORED_IDENTITY_FOR_EVCS;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.ABANDONED;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.HISTORIC;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVcProvenance.EXTERNAL;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVcProvenance.OFFLINE;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVcProvenance.ONLINE;

public class EvcsService {
    private final EvcsClient evcsClient;
    private final ConfigService configService;
    private final StoredIdentityService storedIdentityService;

    @ExcludeFromGeneratedCoverageReport
    public EvcsService(
            EvcsClient evcsClient,
            ConfigService configService,
            StoredIdentityService storedIdentityService) {
        this.evcsClient = evcsClient;
        this.configService = configService;
        this.storedIdentityService = storedIdentityService;
    }

    @ExcludeFromGeneratedCoverageReport
    public EvcsService(ConfigService configService) {
        this.evcsClient = new EvcsClient(configService);
        this.configService = configService;
        this.storedIdentityService = new StoredIdentityService(configService);
    }

    public void storeCompletedIdentity(
            String userId,
            List<VerifiableCredential> credentials,
            List<EvcsGetUserVCDto> currentAndPendingEvcsVcs,
            VotMatchingResult.VotAndProfile strongestMatchedVot,
            Vot achievedVot)
            throws EvcsServiceException {
        persistUserVCs(
                userId,
                credentials,
                currentAndPendingEvcsVcs,
                strongestMatchedVot,
                achievedVot,
                false);
    }

    public void storePendingIdentity(
            String userId,
            List<VerifiableCredential> credentials,
            List<EvcsGetUserVCDto> currentAndPendingEvcsVcs,
            Vot achievedVot)
            throws EvcsServiceException {
        persistUserVCs(userId, credentials, currentAndPendingEvcsVcs, null, achievedVot, true);
    }

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

    public void storeInheritedIdentity(
            String userId,
            VerifiableCredential incomingInheritedIdentity,
            List<VerifiableCredential> existingInheritedIdentity)
            throws EvcsServiceException {
        if (!existingInheritedIdentity.isEmpty()) {
            evcsClient.updateUserVCs(
                    userId,
                    existingInheritedIdentity.stream()
                            .map(
                                    id ->
                                            new EvcsUpdateUserVCsDto(
                                                    getVcSignature(id.getVcString()),
                                                    HISTORIC,
                                                    null))
                            .toList());
        }
        evcsClient.storeUserVCs(
                userId,
                List.of(
                        new EvcsCreateUserVCsDto(
                                incomingInheritedIdentity.getVcString(),
                                CURRENT,
                                new InheritedIdentityMetadata(
                                        incomingInheritedIdentity.getCri().getId()),
                                EXTERNAL)));
    }

    public List<VerifiableCredential> getVerifiableCredentials(
            String userId, String evcsAccessToken, EvcsVCState... states)
            throws CredentialParseException, EvcsServiceException {
        return fetchEvcsVerifiableCredentialsByState(userId, evcsAccessToken, states)
                .values()
                .stream()
                .flatMap(List::stream)
                .toList();
    }

    public List<VerifiableCredential> getVerifiableCredentials(
            String userId, List<EvcsGetUserVCDto> evcsUserVcs, EvcsVCState... states)
            throws CredentialParseException {
        var evcsUserVcsByRequiredState =
                evcsUserVcs.stream()
                        .filter(evcsVc -> List.of(states).contains(evcsVc.state()))
                        .toList();
        return getParsedVerifiableCredentialsFromEvcsResponse(userId, evcsUserVcsByRequiredState)
                .values()
                .stream()
                .flatMap(List::stream)
                .toList();
    }

    public Map<EvcsVCState, List<VerifiableCredential>> fetchEvcsVerifiableCredentialsByState(
            String userId, String evcsAccessToken, EvcsVCState... states)
            throws CredentialParseException, EvcsServiceException {
        var evcsUserVcs = getUserVCs(userId, evcsAccessToken, states);
        return getParsedVerifiableCredentialsFromEvcsResponse(userId, evcsUserVcs);
    }

    private Map<EvcsVCState, List<VerifiableCredential>>
            getParsedVerifiableCredentialsFromEvcsResponse(
                    String userId, List<EvcsGetUserVCDto> evcsUserVcs)
                    throws CredentialParseException {
        Map<EvcsVCState, List<VerifiableCredential>> credentials = new EnumMap<>(EvcsVCState.class);
        for (var vc : evcsUserVcs) {
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

    public List<EvcsGetUserVCDto> getUserVCs(
            String userId, String evcsAccessToken, EvcsVCState... states)
            throws EvcsServiceException {
        return evcsClient.getUserVcs(userId, evcsAccessToken, List.of(states)).vcs();
    }

    private void persistUserVCs(
            String userId,
            List<VerifiableCredential> credentials,
            List<EvcsGetUserVCDto> existingEvcsUserVCs,
            VotMatchingResult.VotAndProfile strongestAchievedVot,
            Vot achievedVot,
            boolean isPendingIdentity)
            throws EvcsServiceException {
        try {
            if (configService.enabled(STORED_IDENTITY_SERVICE)) {
                List<EvcsCreateUserVCsDto> userVCsToStore =
                        credentials.stream()
                                .map(
                                        vc ->
                                                new EvcsCreateUserVCsDto(
                                                        vc.getVcString(),
                                                        isPendingIdentity
                                                                ? PENDING_RETURN
                                                                : CURRENT,
                                                        null,
                                                        ONLINE))
                                .toList();

                EvcsStoredIdentityDto storedIdentityJwt = null;
                if (!isPendingIdentity) {
                    storedIdentityJwt =
                            storedIdentityService.getStoredIdentityForEvcs(
                                    userId, credentials, strongestAchievedVot, achievedVot);
                }
                var putUserVcsDto =
                        new EvcsPutUserVCsDto(userId, userVCsToStore, storedIdentityJwt);

                evcsClient.storeUserVCs(putUserVcsDto);
            } else {
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
                                                        isPendingIdentity
                                                                ? PENDING_RETURN
                                                                : CURRENT,
                                                        null,
                                                        ONLINE))
                                .toList();
                if (!CollectionUtils.isEmpty(existingEvcsUserVCs))
                    updateExistingUserVCs(
                            userId, credentials, existingEvcsUserVCs, isPendingIdentity);
                if (!userVCsToStore.isEmpty()) evcsClient.storeUserVCs(userId, userVCsToStore);
            }
        } catch (FailedToCreateStoredIdentityForEvcsException e) {
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, FAILED_TO_CREATE_STORED_IDENTITY_FOR_EVCS);
        }
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
                                            vc.metadata() == null
                                                    || vc.metadata().get("inheritedIdentity")
                                                            == null) // Don't update inherited
                            // identity VCs
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
