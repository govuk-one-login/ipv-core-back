package uk.gov.di.ipv.core.library.evcs.service;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.client.EvcsClient;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsGetUserVCDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsPostIdentityDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsUpdateUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.exception.FailedToCreateStoredIdentityForEvcsException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;

import java.net.http.HttpResponse;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.ABANDONED;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.PENDING_RETURN;
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

    public List<VerifiableCredential> getVerifiableCredentials(
            String userId, String evcsAccessToken, EvcsVCState... states)
            throws CredentialParseException, EvcsServiceException {
        return fetchEvcsVerifiableCredentialsByState(userId, evcsAccessToken, false, states)
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
        return getParsedVerifiableCredentialsFromEvcsResponse(
                        userId, evcsUserVcsByRequiredState, false)
                .values()
                .stream()
                .flatMap(List::stream)
                .toList();
    }

    public Map<EvcsVCState, List<VerifiableCredential>> fetchEvcsVerifiableCredentialsByState(
            String userId, String evcsAccessToken, boolean includeCimit, EvcsVCState... states)
            throws CredentialParseException, EvcsServiceException {
        var evcsUserVcs = getUserVCs(userId, evcsAccessToken, states);
        return getParsedVerifiableCredentialsFromEvcsResponse(userId, evcsUserVcs, includeCimit);
    }

    private Map<EvcsVCState, List<VerifiableCredential>>
            getParsedVerifiableCredentialsFromEvcsResponse(
                    String userId, List<EvcsGetUserVCDto> evcsUserVcs, boolean includeCimit)
                    throws CredentialParseException {
        var credentials = new EnumMap<EvcsVCState, List<VerifiableCredential>>(EvcsVCState.class);

        try {
            var issuerCris = configService.getIssuerCris();
            var cimitComponentId = configService.getCimitComponentId();

            for (var vc : evcsUserVcs) {
                var jwt = SignedJWT.parse(vc.vc());
                var issuer = jwt.getJWTClaimsSet().getIssuer();

                // With SIS, we now store the CIMIT VC. We don't want to add this to the
                // credential bundle so we skip the VC if it's from CIMIT.
                // PYIC-8393 Allow overriding of this behaviour just for verification of stored
                // identities
                if (!includeCimit && cimitComponentId.equals(issuer)) {
                    continue;
                }

                var cri = issuerCris.get(issuer);
                // PYIC-8393 Allow overriding of this behaviour just for verification of stored
                // identities
                if (cri == null && cimitComponentId.equals(issuer)) {
                    cri = Cri.CIMIT;
                }
                if (cri == null) {
                    throw new CredentialParseException(
                            String.format(
                                    "Failed to find credential issuer for vc issuer: %s in %s",
                                    issuer, issuerCris));
                }

                var credential = VerifiableCredential.fromValidJwt(userId, cri, jwt);
                if (!credentials.containsKey(vc.state())) {
                    credentials.put(vc.state(), new ArrayList<>());
                }
                credentials.get(vc.state()).add(credential);
            }
        } catch (ParseException e) {
            throw new CredentialParseException(
                    "Encountered a parsing error while attempting to parse evcs credentials", e);
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

    public void storePendingIdentityWithPostIdentity(
            String userId, List<VerifiableCredential> credentials) throws EvcsServiceException {
        var postIdentityDto = createPendingPostIdentityDto(userId, credentials);
        evcsClient.storeUserIdentity(postIdentityDto);
    }

    public HttpResponse<String> storeCompletedIdentityWithPostIdentity(
            String userId,
            List<VerifiableCredential> credentials,
            VotMatchingResult.VotAndProfile strongestAchievedVot,
            Vot achievedVot)
            throws FailedToCreateStoredIdentityForEvcsException, EvcsServiceException {
        var postIdentityDto =
                createCompletedPostIdentityDto(
                        userId, credentials, strongestAchievedVot, achievedVot);
        return evcsClient.storeUserIdentity(postIdentityDto);
    }

    private EvcsPostIdentityDto createCompletedPostIdentityDto(
            String userId,
            List<VerifiableCredential> credentials,
            VotMatchingResult.VotAndProfile strongestAchievedVot,
            Vot achievedVot)
            throws FailedToCreateStoredIdentityForEvcsException {
        var storedIdentityJwt =
                storedIdentityService.getStoredIdentityForEvcs(
                        userId, credentials, strongestAchievedVot, achievedVot);

        return new EvcsPostIdentityDto(
                userId,
                credentials.stream()
                        .map(
                                vc ->
                                        new EvcsCreateUserVCsDto(
                                                vc.getVcString(), CURRENT, null, ONLINE))
                        .toList(),
                storedIdentityJwt);
    }

    private EvcsPostIdentityDto createPendingPostIdentityDto(
            String userId, List<VerifiableCredential> credentials) {
        return new EvcsPostIdentityDto(
                userId,
                credentials.stream()
                        .map(
                                vc ->
                                        new EvcsCreateUserVCsDto(
                                                vc.getVcString(), PENDING_RETURN, null, ONLINE))
                        .toList(),
                null);
    }

    public void storeCompletedOrPendingIdentityWithPostVcs(
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

    public HttpResponse<String> storeStoredIdentityRecord(
            String userId,
            List<VerifiableCredential> credentials,
            VotMatchingResult.VotAndProfile strongestAchievedVot,
            Vot achievedVot)
            throws FailedToCreateStoredIdentityForEvcsException, EvcsServiceException {
        var storedIdentityJwt =
                storedIdentityService.getStoredIdentityForEvcs(
                        userId, credentials, strongestAchievedVot, achievedVot);

        var evcsStoreIdentityDto = new EvcsPostIdentityDto(userId, null, storedIdentityJwt);

        return evcsClient.storeUserIdentity(evcsStoreIdentityDto);
    }

    public void invalidateStoredIdentityRecord(String userId) throws EvcsServiceException {
        evcsClient.invalidateStoredIdentityRecord(userId);
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
