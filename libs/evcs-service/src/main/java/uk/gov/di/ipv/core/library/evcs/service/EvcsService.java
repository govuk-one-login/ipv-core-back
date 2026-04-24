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
import uk.gov.di.ipv.core.library.evcs.enums.EvcsVcProvenance;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.exception.FailedToCreateStoredIdentityForEvcsException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;

import java.net.http.HttpResponse;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Predicate;
import java.util.stream.Stream;

import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.ABANDONED;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.HISTORIC;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVcProvenance.OFFLINE;

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

    public void storeCompletedOrPendingIdentityWithPostVcs(
            String userId,
            List<VerifiableCredential> credentials,
            List<EvcsGetUserVCDto> existingEvcsUserVCs,
            boolean isPendingIdentity)
            throws EvcsServiceException {

        var evcsCreateUserVCsDtos =
                mapNewVcsToEvcsCreateUserVCsDto(
                        findNewUserVcs(credentials, existingEvcsUserVCs),
                        isPendingIdentity ? PENDING_RETURN : CURRENT);

        if (!CollectionUtils.isEmpty(existingEvcsUserVCs)) {
            var existingVcsToUpdate =
                    mapAndUpdateStateOfExistingUserVcs(
                            credentials,
                            existingEvcsUserVCs,
                            this::mapExistingVcsToEvcsUpdateUserVCsDto,
                            isPendingIdentity);
            if (!existingVcsToUpdate.isEmpty()) {
                evcsClient.updateUserVCs(userId, existingVcsToUpdate);
            }
        }
        if (!evcsCreateUserVCsDtos.isEmpty()) {
            evcsClient.storeUserVCs(userId, evcsCreateUserVCsDtos);
        }
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

        var evcsStoreIdentityDto = new EvcsPostIdentityDto(userId, null, null, storedIdentityJwt);

        return evcsClient.storeUserIdentity(evcsStoreIdentityDto);
    }

    public HttpResponse<String> storeStoredIdentityRecordAndVcs(
            String userId,
            String govukSigninJourneyId,
            List<VerifiableCredential> credentials,
            List<EvcsGetUserVCDto> existingEvcsUserVcs,
            VotMatchingResult.VotAndProfile strongestAchievedVot,
            Vot achievedVot)
            throws FailedToCreateStoredIdentityForEvcsException, EvcsServiceException {
        var storedIdentityJwt =
                storedIdentityService.getStoredIdentityForEvcs(
                        userId, credentials, strongestAchievedVot, achievedVot);

        var evcsCreateUserVCsDtos =
                mapNewVcsToEvcsCreateUserVCsDto(
                        findNewUserVcs(credentials, existingEvcsUserVcs), CURRENT);

        var existingVcsToUpdate =
                mapAndUpdateStateOfExistingUserVcs(
                        credentials,
                        existingEvcsUserVcs,
                        this::mapExistingVcsToEvcsCreateUserVCsDto,
                        false);

        var vcToCreateAndUpdate =
                Stream.concat(evcsCreateUserVCsDtos.stream(), existingVcsToUpdate.stream())
                        .toList();
        var evcsStoreIdentityDto =
                new EvcsPostIdentityDto(
                        userId,
                        vcToCreateAndUpdate.isEmpty() ? null : govukSigninJourneyId,
                        vcToCreateAndUpdate.isEmpty() ? null : vcToCreateAndUpdate,
                        storedIdentityJwt);

        return evcsClient.storeUserIdentity(evcsStoreIdentityDto);
    }

    private List<EvcsCreateUserVCsDto> mapNewVcsToEvcsCreateUserVCsDto(
            List<VerifiableCredential> credentials, EvcsVCState newState) {
        return credentials.stream()
                .map(
                        vc ->
                                new EvcsCreateUserVCsDto(
                                        vc.getVcString(), newState, null, EvcsVcProvenance.ONLINE))
                .toList();
    }

    private List<EvcsUpdateUserVCsDto> mapExistingVcsToEvcsUpdateUserVCsDto(
            List<EvcsGetUserVCDto> existingVcs, EvcsVCState newState) {
        return existingVcs.stream()
                .map(
                        existingVc ->
                                new EvcsUpdateUserVCsDto(
                                        getVcSignature(existingVc.vc()), newState, null))
                .toList();
    }

    private List<EvcsCreateUserVCsDto> mapExistingVcsToEvcsCreateUserVCsDto(
            List<EvcsGetUserVCDto> existingVcs, EvcsVCState newState) {
        return existingVcs.stream()
                .map(
                        existingVc ->
                                new EvcsCreateUserVCsDto(
                                        existingVc.vc(), newState, existingVc.metadata(), null))
                .toList();
    }

    private <T> List<T> mapAndUpdateStateOfExistingUserVcs(
            List<VerifiableCredential> credentials,
            List<EvcsGetUserVCDto> existingEvcsUserVCs,
            BiFunction<List<EvcsGetUserVCDto>, EvcsVCState, List<T>> mapper,
            boolean isPendingIdentity) {
        var existingPendingReturnUserVcsNotInSessionToUpdate =
                mapper.apply(
                        findExistingVcsNotInSessionCredentials(
                                credentials,
                                existingEvcsUserVCs,
                                evcsGetUserVCDto ->
                                        evcsGetUserVCDto.state().equals(PENDING_RETURN)),
                        ABANDONED);

        if (!isPendingIdentity) {
            var existingPendingReturnUserVcsInSessionToUpdate =
                    mapper.apply(
                            findExistingVcsInSessionCredentials(
                                    credentials,
                                    existingEvcsUserVCs,
                                    evcsGetUserVCDto ->
                                            evcsGetUserVCDto.state().equals(PENDING_RETURN)),
                            CURRENT);
            var existingCurrentUserVcsNotInSessionToUpdate =
                    mapper.apply(
                            findExistingVcsNotInSessionCredentials(
                                    credentials,
                                    existingEvcsUserVCs,
                                    evcsGetUserVCDto -> evcsGetUserVCDto.state().equals(CURRENT)),
                            HISTORIC);

            return Stream.of(
                            existingPendingReturnUserVcsNotInSessionToUpdate,
                            existingPendingReturnUserVcsInSessionToUpdate,
                            existingCurrentUserVcsNotInSessionToUpdate)
                    .flatMap(Collection::stream)
                    .toList();
        }

        return existingPendingReturnUserVcsNotInSessionToUpdate;
    }

    private List<VerifiableCredential> findNewUserVcs(
            List<VerifiableCredential> sessionCredentials, List<EvcsGetUserVCDto> existingEvcsVCs) {
        return sessionCredentials.stream()
                .filter(
                        credential ->
                                existingEvcsVCs.stream()
                                        .noneMatch(
                                                evcsVc ->
                                                        evcsVc.vc()
                                                                .equals(credential.getVcString())))
                .toList();
    }

    private List<EvcsGetUserVCDto> findExistingVcsNotInSessionCredentials(
            List<VerifiableCredential> credentials,
            List<EvcsGetUserVCDto> existingEvcsUserVCs,
            Predicate<EvcsGetUserVCDto> condition) {
        return existingEvcsUserVCs.stream()
                .filter(condition)
                .filter(
                        existingVc ->
                                credentials.stream()
                                        .noneMatch(
                                                credential ->
                                                        credential
                                                                .getVcString()
                                                                .equals(existingVc.vc())))
                .toList();
    }

    private List<EvcsGetUserVCDto> findExistingVcsInSessionCredentials(
            List<VerifiableCredential> credentials,
            List<EvcsGetUserVCDto> existingEvcsUserVCs,
            Predicate<EvcsGetUserVCDto> condition) {
        return existingEvcsUserVCs.stream()
                .filter(condition)
                .filter(
                        vc ->
                                credentials.stream()
                                        .anyMatch(
                                                credential ->
                                                        credential.getVcString().equals(vc.vc())))
                .toList();
    }

    public void invalidateStoredIdentityRecord(String userId) throws EvcsServiceException {
        evcsClient.invalidateStoredIdentityRecord(userId);
    }

    public void markHistoricInEvcs(String userId, List<VerifiableCredential> vcs)
            throws EvcsServiceException {
        var vcsToUpdate =
                vcs.stream()
                        .map(
                                vc ->
                                        new EvcsUpdateUserVCsDto(
                                                getVcSignature(vc.getVcString()),
                                                EvcsVCState.HISTORIC,
                                                null))
                        .toList();
        if (!vcsToUpdate.isEmpty()) {
            evcsClient.updateUserVCs(userId, vcsToUpdate);
        }
    }

    private static String getVcSignature(String vcString) {
        return vcString.split("\\.")[2];
    }
}
