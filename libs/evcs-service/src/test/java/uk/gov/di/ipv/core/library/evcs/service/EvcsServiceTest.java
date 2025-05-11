package uk.gov.di.ipv.core.library.evcs.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.client.EvcsClient;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsGetUserVCDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsGetUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsPutUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsStoredIdentityDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsUpdateUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.NoCriForIssuerException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.STORED_IDENTITY_SERVICE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_CONSTRUCT_EVCS_URI;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_EVCS_REQUEST_BODY;
import static uk.gov.di.ipv.core.library.enums.Vot.P1;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.HISTORIC;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVcProvenance.OFFLINE;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVcProvenance.ONLINE;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressOne;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fPassportPhotoM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL200;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL200NoEvidence;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL250;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebDrivingPermitDvaValid;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebDrivingPermitDvlaValid;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.L1A;

@ExtendWith(MockitoExtension.class)
class EvcsServiceTest {
    private static final VerifiableCredential VC_DRIVING_PERMIT_TEST = vcWebDrivingPermitDvaValid();
    private static final VerifiableCredential VC_ADDRESS_TEST = vcAddressOne();
    private static final VerifiableCredential VC_PASSPORT_NON_DCMAW_SUCCESSFUL_TEST =
            vcWebPassportSuccessful();
    private static final VerifiableCredential VC_F2F = vcF2fPassportPhotoM1a();
    private static final List<VerifiableCredential> VERIFIABLE_CREDENTIALS =
            List.of(VC_DRIVING_PERMIT_TEST, VC_ADDRESS_TEST, vcExperianFraudM1a());
    private static final List<VerifiableCredential> VERIFIABLE_CREDENTIALS_ONE_EXIST_IN_EVCS =
            List.of(
                    VC_DRIVING_PERMIT_TEST,
                    VC_ADDRESS_TEST,
                    vcExperianFraudM1a(),
                    VC_PASSPORT_NON_DCMAW_SUCCESSFUL_TEST);
    private static final List<VerifiableCredential> VERIFIABLE_CREDENTIALS_ALL_EXIST_IN_EVCS =
            List.of(VC_DRIVING_PERMIT_TEST, VC_ADDRESS_TEST, VC_F2F);
    private static final String TEST_USER_ID = "a-user-id";

    private static final String TEST_EVCS_ACCESS_TOKEN = "TEST_EVCS_ACCESS_TOKEN";
    private static final List<EvcsGetUserVCDto> EVCS_GET_USER_VC_DTO =
            List.of(
                    new EvcsGetUserVCDto(
                            vcAddressTwo().getVcString(),
                            EvcsVCState.CURRENT,
                            Map.of(
                                    "reason", "testing",
                                    "txmaEventId", "txma-event-id-2",
                                    "timestampMs", "1714478033959")),
                    new EvcsGetUserVCDto(
                            vcWebDrivingPermitDvlaValid().getVcString(),
                            EvcsVCState.PENDING_RETURN,
                            Map.of(
                                    "reason", "testing",
                                    "txmaEventId", "txma-event-id-2",
                                    "timestampMs", "1714478033959")),
                    new EvcsGetUserVCDto(
                            VC_PASSPORT_NON_DCMAW_SUCCESSFUL_TEST.getVcString(),
                            EvcsVCState.CURRENT,
                            Map.of(
                                    "reason", "testing",
                                    "txmaEventId", "txma-event-id-2",
                                    "timestampMs", "1714478033959")));

    private static final VotMatchingResult.VotAndProfile STRONGEST_MATCHED_VOT =
            new VotMatchingResult.VotAndProfile(P1, Optional.of(L1A));
    private static final Vot ACHIEVED_VOT = P1;
    private static ClientOAuthSessionItem clientOAuthSessionItem;

    @Captor ArgumentCaptor<List<EvcsCreateUserVCsDto>> evcsCreateUserVCsDtosCaptor;
    @Captor ArgumentCaptor<List<EvcsUpdateUserVCsDto>> evcsUpdateUserVCsDtosCaptor;
    @Captor ArgumentCaptor<EvcsPutUserVCsDto> evcsPutUserVCsDtoCaptor;
    @Captor ArgumentCaptor<String> stringArgumentCaptor;

    @Mock EvcsClient mockEvcsClient;
    @Mock ConfigService mockConfigService;
    @Mock StoredIdentityService mockStoredIdentityService;
    @InjectMocks EvcsService evcsService;

    @BeforeEach
    void setUp() {
        clientOAuthSessionItem = ClientOAuthSessionItem.builder().userId(TEST_USER_ID).build();
    }

    @Test
    void testStoreIdentity_whenNoExistingEvcsUserVCs() throws Exception {
        // Arrange
        // Act
        evcsService.storeCompletedIdentity(
                TEST_USER_ID,
                VERIFIABLE_CREDENTIALS,
                List.of(),
                STRONGEST_MATCHED_VOT,
                ACHIEVED_VOT);
        // Assert
        InOrder mockOrderVerifier = inOrder(mockEvcsClient);
        mockOrderVerifier.verify(mockEvcsClient, times(0)).updateUserVCs(any(), any());
        mockOrderVerifier
                .verify(mockEvcsClient)
                .storeUserVCs(any(), evcsCreateUserVCsDtosCaptor.capture());
        var userVCsForEvcs = evcsCreateUserVCsDtosCaptor.getValue();
        assertEquals(
                3,
                (userVCsForEvcs.stream()
                        .filter(dto -> dto.state().equals(EvcsVCState.CURRENT))
                        .count()));
        assertFalse(
                userVCsForEvcs.stream().anyMatch(dto -> !dto.state().equals(EvcsVCState.CURRENT)));
        assertFalse(userVCsForEvcs.stream().anyMatch(dto -> !dto.provenance().equals(ONLINE)));
    }

    @Test
    void testStorePendingIdentity_onSuccessfulJourney_for_incompleteF2F() throws Exception {
        // Arrange
        // Act
        evcsService.storePendingIdentity(
                TEST_USER_ID, VERIFIABLE_CREDENTIALS_ONE_EXIST_IN_EVCS, List.of(), ACHIEVED_VOT);
        // Assert
        InOrder mockOrderVerifier = inOrder(mockEvcsClient);
        mockOrderVerifier
                .verify(mockEvcsClient, times(0))
                .updateUserVCs(any(), evcsUpdateUserVCsDtosCaptor.capture());
        mockOrderVerifier
                .verify(mockEvcsClient)
                .storeUserVCs(any(), evcsCreateUserVCsDtosCaptor.capture());
        var userVCsForEvcs = evcsCreateUserVCsDtosCaptor.getValue();
        assertFalse(
                userVCsForEvcs.stream()
                        .anyMatch(dto -> !dto.state().equals(EvcsVCState.PENDING_RETURN)));
    }

    @Test
    void storePendingIdentityShouldStorePendingIdentityWithPutMethod() throws Exception {
        // Arrange
        when(mockConfigService.enabled(STORED_IDENTITY_SERVICE)).thenReturn(true);

        // Act
        evcsService.storePendingIdentity(
                TEST_USER_ID, List.of(VC_ADDRESS_TEST), List.of(), ACHIEVED_VOT);

        // Assert
        InOrder mockOrderVerifier = inOrder(mockEvcsClient);
        mockOrderVerifier
                .verify(mockEvcsClient, times(0))
                .updateUserVCs(any(), evcsUpdateUserVCsDtosCaptor.capture());
        mockOrderVerifier.verify(mockEvcsClient, times(0)).storeUserVCs(any(), any());
        mockOrderVerifier.verify(mockEvcsClient).storeUserVCs(evcsPutUserVCsDtoCaptor.capture());

        assertEquals(
                clientOAuthSessionItem.getUserId(), evcsPutUserVCsDtoCaptor.getValue().userId());
        assertEquals(
                VC_ADDRESS_TEST.getVcString(),
                evcsPutUserVCsDtoCaptor.getValue().vcs().get(0).vc());
        assertEquals(PENDING_RETURN, evcsPutUserVCsDtoCaptor.getValue().vcs().get(0).state());
        assertEquals(ONLINE, evcsPutUserVCsDtoCaptor.getValue().vcs().get(0).provenance());
        assertNull(evcsPutUserVCsDtoCaptor.getValue().si());
    }

    @Test
    void testStoreIdentity_for_6MFCJourney() throws Exception {
        // Act
        evcsService.storeCompletedIdentity(
                TEST_USER_ID,
                VERIFIABLE_CREDENTIALS_ONE_EXIST_IN_EVCS,
                EVCS_GET_USER_VC_DTO,
                STRONGEST_MATCHED_VOT,
                ACHIEVED_VOT);
        // Assert
        InOrder mockOrderVerifier = inOrder(mockEvcsClient);
        mockOrderVerifier
                .verify(mockEvcsClient)
                .updateUserVCs(any(), evcsUpdateUserVCsDtosCaptor.capture());
        mockOrderVerifier
                .verify(mockEvcsClient)
                .storeUserVCs(any(), evcsCreateUserVCsDtosCaptor.capture());

        var evcsUserVCsToUpdate = evcsUpdateUserVCsDtosCaptor.getValue();
        assertEquals(
                1,
                (evcsUserVCsToUpdate.stream()
                        .filter(dto -> dto.state().equals(EvcsVCState.HISTORIC))
                        .count()));
        var userVCsForEvcs = evcsCreateUserVCsDtosCaptor.getValue();
        assertEquals(
                3,
                (userVCsForEvcs.stream()
                        .filter(dto -> dto.state().equals(EvcsVCState.CURRENT))
                        .count()));
    }

    @Test
    void testStoreCompleteIdentity_whenAllVCsExistInEvcs_withCurrentState() throws Exception {
        // Arrange
        List<EvcsGetUserVCDto> evcsGetUserVcsWithCurrentStateAllExistingDto =
                List.of(
                        new EvcsGetUserVCDto(
                                VC_ADDRESS_TEST.getVcString(),
                                EvcsVCState.CURRENT,
                                Map.of("reason", "testing")),
                        new EvcsGetUserVCDto(
                                VC_DRIVING_PERMIT_TEST.getVcString(),
                                EvcsVCState.CURRENT,
                                Map.of("reason", "testing")),
                        new EvcsGetUserVCDto(
                                VC_F2F.getVcString(),
                                EvcsVCState.CURRENT,
                                Map.of("reason", "testing")));
        // Act
        evcsService.storeCompletedIdentity(
                TEST_USER_ID,
                VERIFIABLE_CREDENTIALS_ALL_EXIST_IN_EVCS,
                evcsGetUserVcsWithCurrentStateAllExistingDto,
                STRONGEST_MATCHED_VOT,
                ACHIEVED_VOT);
        // Assert
        InOrder mockOrderVerifier = inOrder(mockEvcsClient);
        mockOrderVerifier.verify(mockEvcsClient, times(0)).updateUserVCs(any(), any());
        mockOrderVerifier.verify(mockEvcsClient, times(0)).storeUserVCs(any(), any());
    }

    @Test
    void testStoreCompleteIdentity_whenAllVCsExistInEvcs_inSession_withPendingReturnState()
            throws Exception {
        // Arrange
        List<EvcsGetUserVCDto> evcsGetUserVcsWithPendingAllExistingDto =
                List.of(
                        new EvcsGetUserVCDto(
                                VC_ADDRESS_TEST.getVcString(),
                                EvcsVCState.PENDING_RETURN,
                                Map.of("reason", "testing")),
                        new EvcsGetUserVCDto(
                                VC_DRIVING_PERMIT_TEST.getVcString(),
                                EvcsVCState.PENDING_RETURN,
                                Map.of("reason", "testing")),
                        new EvcsGetUserVCDto(
                                VC_F2F.getVcString(),
                                EvcsVCState.PENDING_RETURN,
                                Map.of("reason", "testing")));
        // Act
        evcsService.storeCompletedIdentity(
                TEST_USER_ID,
                VERIFIABLE_CREDENTIALS_ALL_EXIST_IN_EVCS,
                evcsGetUserVcsWithPendingAllExistingDto,
                STRONGEST_MATCHED_VOT,
                ACHIEVED_VOT);
        // Assert
        InOrder mockOrderVerifier = inOrder(mockEvcsClient);
        mockOrderVerifier
                .verify(mockEvcsClient, times(1))
                .updateUserVCs(any(), evcsUpdateUserVCsDtosCaptor.capture());
        var userVCsToUpdate = evcsUpdateUserVCsDtosCaptor.getValue();
        assertEquals(
                3,
                (userVCsToUpdate.stream()
                        .filter(dto -> dto.state().equals(EvcsVCState.CURRENT))
                        .count()));
        mockOrderVerifier.verify(mockEvcsClient, times(0)).storeUserVCs(any(), any());
    }

    @Test
    void testStoreCompleteIdentity_whenAllVCsExistInEvcs_notInSession_withPendingReturnState()
            throws Exception {
        // Arrange
        List<EvcsGetUserVCDto> evcsGetUserVcsWithPendingAllExistingDto =
                List.of(
                        new EvcsGetUserVCDto(
                                VC_ADDRESS_TEST.getVcString(),
                                EvcsVCState.PENDING_RETURN,
                                Map.of("reason", "testing")),
                        new EvcsGetUserVCDto(
                                VC_DRIVING_PERMIT_TEST.getVcString(),
                                EvcsVCState.PENDING_RETURN,
                                Map.of("reason", "testing")),
                        new EvcsGetUserVCDto(
                                VC_F2F.getVcString(),
                                EvcsVCState.PENDING_RETURN,
                                Map.of("reason", "testing")));
        // Act
        evcsService.storeCompletedIdentity(
                TEST_USER_ID,
                Collections.emptyList(),
                evcsGetUserVcsWithPendingAllExistingDto,
                STRONGEST_MATCHED_VOT,
                ACHIEVED_VOT);
        // Assert
        InOrder mockOrderVerifier = inOrder(mockEvcsClient);
        mockOrderVerifier
                .verify(mockEvcsClient, times(1))
                .updateUserVCs(any(), evcsUpdateUserVCsDtosCaptor.capture());
        var userVCsToUpdate = evcsUpdateUserVCsDtosCaptor.getValue();
        assertEquals(
                3,
                (userVCsToUpdate.stream()
                        .filter(dto -> dto.state().equals(EvcsVCState.ABANDONED))
                        .count()));
        mockOrderVerifier.verify(mockEvcsClient, times(0)).storeUserVCs(any(), any());
    }

    @Test
    void storeCompletedIdentityShouldNotUpdateInheritedIdentity() throws Exception {
        var vcsInEvcs =
                List.of(
                        new EvcsGetUserVCDto(
                                vcHmrcMigrationPCL200().getVcString(),
                                EvcsVCState.CURRENT,
                                Map.of("inheritedIdentity", Cri.HMRC_MIGRATION.getId())));
        // Act
        evcsService.storeCompletedIdentity(
                TEST_USER_ID,
                VERIFIABLE_CREDENTIALS_ALL_EXIST_IN_EVCS,
                vcsInEvcs,
                STRONGEST_MATCHED_VOT,
                ACHIEVED_VOT);
        // Assert
        InOrder mockOrderVerifier = inOrder(mockEvcsClient);

        mockOrderVerifier.verify(mockEvcsClient, never()).updateUserVCs(any(), any());
        mockOrderVerifier.verify(mockEvcsClient, times(1)).storeUserVCs(any(), any());
    }

    @Test
    void storeCompletedIdentityShouldStoreCompletedIdentityWithPutMethod() throws Exception {
        // Arrange
        var testVcs = List.of(VC_ADDRESS_TEST);
        var testSiJwt = "test.si.jwt";
        when(mockConfigService.enabled(STORED_IDENTITY_SERVICE)).thenReturn(true);
        when(mockStoredIdentityService.getStoredIdentityForEvcs(
                        TEST_USER_ID, testVcs, STRONGEST_MATCHED_VOT, ACHIEVED_VOT))
                .thenReturn(new EvcsStoredIdentityDto(testSiJwt, P1));

        // Act
        evcsService.storeCompletedIdentity(
                TEST_USER_ID, testVcs, List.of(), STRONGEST_MATCHED_VOT, ACHIEVED_VOT);

        // Assert
        verify(mockEvcsClient).storeUserVCs(evcsPutUserVCsDtoCaptor.capture());

        assertEquals(
                clientOAuthSessionItem.getUserId(), evcsPutUserVCsDtoCaptor.getValue().userId());
        assertEquals(
                VC_ADDRESS_TEST.getVcString(),
                evcsPutUserVCsDtoCaptor.getValue().vcs().get(0).vc());
        assertEquals(CURRENT, evcsPutUserVCsDtoCaptor.getValue().vcs().get(0).state());
        assertEquals(ONLINE, evcsPutUserVCsDtoCaptor.getValue().vcs().get(0).provenance());
        assertEquals(testSiJwt, evcsPutUserVCsDtoCaptor.getValue().si().jwt());
        assertEquals(P1, evcsPutUserVCsDtoCaptor.getValue().si().vot());

        verify(mockEvcsClient, never()).updateUserVCs(any(), any());
        verify(mockEvcsClient, never()).storeUserVCs(any(), any());
    }

    @Test
    void storeMigratedIdentityShouldStoreVcsWithCurrentState() throws EvcsServiceException {
        evcsService.storeMigratedIdentity(TEST_USER_ID, List.of(VC_ADDRESS_TEST));

        verify(mockEvcsClient)
                .storeUserVCs(
                        stringArgumentCaptor.capture(), evcsCreateUserVCsDtosCaptor.capture());

        assertEquals(TEST_USER_ID, stringArgumentCaptor.getValue());
        assertEquals(
                VC_ADDRESS_TEST.getVcString(), evcsCreateUserVCsDtosCaptor.getValue().get(0).vc());
        assertEquals(CURRENT, evcsCreateUserVCsDtosCaptor.getValue().get(0).state());
        assertEquals(ONLINE, evcsCreateUserVCsDtosCaptor.getValue().get(0).provenance());
    }

    @Test
    void storeAsyncVcShouldStoreVcWithPendingReturnState() throws EvcsServiceException {
        evcsService.storePendingVc(VC_ADDRESS_TEST);

        verify(mockEvcsClient)
                .storeUserVCs(
                        stringArgumentCaptor.capture(), evcsCreateUserVCsDtosCaptor.capture());

        assertEquals(VC_ADDRESS_TEST.getUserId(), stringArgumentCaptor.getValue());
        assertEquals(
                VC_ADDRESS_TEST.getVcString(), evcsCreateUserVCsDtosCaptor.getValue().get(0).vc());
        assertEquals(PENDING_RETURN, evcsCreateUserVCsDtosCaptor.getValue().get(0).state());
        assertEquals(OFFLINE, evcsCreateUserVCsDtosCaptor.getValue().get(0).provenance());
    }

    @Test
    void updatePendingIdentityShouldUpdateStateToAbandoned() throws EvcsServiceException {
        EvcsGetUserVCsDto evcsGetUserVcsWithPendingAllExistingDto =
                new EvcsGetUserVCsDto(
                        List.of(
                                new EvcsGetUserVCDto(
                                        VC_ADDRESS_TEST.getVcString(),
                                        EvcsVCState.PENDING_RETURN,
                                        Map.of("reason", "testing")),
                                new EvcsGetUserVCDto(
                                        vcExperianFraudM1a().getVcString(),
                                        EvcsVCState.PENDING_RETURN,
                                        Map.of("reason", "testing"))));
        when(mockEvcsClient.getUserVcs(
                        TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, List.of(PENDING_RETURN)))
                .thenReturn(evcsGetUserVcsWithPendingAllExistingDto);
        evcsService.abandonPendingIdentity(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN);

        InOrder mockOrderVerifier = inOrder(mockEvcsClient);
        mockOrderVerifier
                .verify(mockEvcsClient)
                .getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, List.of(PENDING_RETURN));
        mockOrderVerifier
                .verify(mockEvcsClient)
                .updateUserVCs(
                        stringArgumentCaptor.capture(), evcsUpdateUserVCsDtosCaptor.capture());

        var userVCsToUpdate = evcsUpdateUserVCsDtosCaptor.getValue();
        assertEquals(
                2,
                (userVCsToUpdate.stream()
                        .filter(dto -> dto.state().equals(EvcsVCState.ABANDONED))
                        .count()));
    }

    @Test
    void testGetVerifiableCredentials()
            throws CredentialParseException, NoCriForIssuerException, EvcsServiceException {
        // Arrange
        when(mockConfigService.getCriByIssuer(vcAddressM1a().getClaimsSet().getIssuer()))
                .thenReturn(Cri.ADDRESS);
        when(mockConfigService.getCriByIssuer(vcWebPassportSuccessful().getClaimsSet().getIssuer()))
                .thenReturn(Cri.DCMAW);

        when(mockEvcsClient.getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, List.of(CURRENT)))
                .thenReturn(
                        new EvcsGetUserVCsDto(
                                List.of(
                                        new EvcsGetUserVCDto(
                                                vcAddressM1a().getVcString(),
                                                EvcsVCState.CURRENT,
                                                null),
                                        new EvcsGetUserVCDto(
                                                vcWebPassportSuccessful().getVcString(),
                                                EvcsVCState.CURRENT,
                                                null))));

        // Act
        var vcs =
                evcsService.getVerifiableCredentials(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, CURRENT);
        // Assert
        assertEquals(
                2,
                (vcs.stream()
                        .filter(
                                vc ->
                                        vc.getCri().equals(Cri.ADDRESS)
                                                || vc.getCri().equals(Cri.DCMAW))
                        .count()));
    }

    @Test
    void testGetVerifiableCredentialsShouldErrorWhenCriNotFound()
            throws NoCriForIssuerException, EvcsServiceException {
        // Arrange
        when(mockConfigService.getCriByIssuer(any()))
                .thenThrow(new NoCriForIssuerException("not found"));

        when(mockEvcsClient.getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, List.of(CURRENT)))
                .thenReturn(
                        new EvcsGetUserVCsDto(
                                List.of(
                                        new EvcsGetUserVCDto(
                                                vcExperianFraudM1a().getVcString(),
                                                EvcsVCState.CURRENT,
                                                null),
                                        new EvcsGetUserVCDto(
                                                vcWebPassportSuccessful().getVcString(),
                                                EvcsVCState.CURRENT,
                                                null))));

        // Act/Assert
        assertThrows(
                CredentialParseException.class,
                () ->
                        evcsService.getVerifiableCredentials(
                                TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, CURRENT));
    }

    @Test
    void getVerifiableCredentialsShouldReturnParsedVcsWhenGivenEvcsVcs() throws Exception {
        // Arrange
        var evcsVcs =
                List.of(
                        new EvcsGetUserVCDto(vcAddressM1a().getVcString(), CURRENT, null),
                        new EvcsGetUserVCDto(
                                vcWebPassportSuccessful().getVcString(), CURRENT, null));

        when(mockConfigService.getCriByIssuer(vcAddressM1a().getClaimsSet().getIssuer()))
                .thenReturn(Cri.ADDRESS);
        when(mockConfigService.getCriByIssuer(vcWebPassportSuccessful().getClaimsSet().getIssuer()))
                .thenReturn(Cri.DCMAW);

        // Act
        var vcs = evcsService.getVerifiableCredentials(TEST_USER_ID, evcsVcs, CURRENT);
        // Assert
        assertEquals(
                2,
                (vcs.stream()
                        .filter(
                                vc ->
                                        vc.getCri().equals(Cri.ADDRESS)
                                                || vc.getCri().equals(Cri.DCMAW))
                        .count()));
    }

    @Test
    void getVerifiableCredentialsSupportsMultipleStates() throws Exception {
        // Arrange
        var evcsVcs =
                List.of(
                        new EvcsGetUserVCDto(vcAddressM1a().getVcString(), CURRENT, null),
                        new EvcsGetUserVCDto(
                                vcWebPassportSuccessful().getVcString(), PENDING_RETURN, null));

        when(mockConfigService.getCriByIssuer(vcAddressM1a().getClaimsSet().getIssuer()))
                .thenReturn(Cri.ADDRESS);
        when(mockConfigService.getCriByIssuer(vcWebPassportSuccessful().getClaimsSet().getIssuer()))
                .thenReturn(Cri.DCMAW);

        // Act
        var vcs =
                evcsService.getVerifiableCredentials(
                        TEST_USER_ID, evcsVcs, CURRENT, PENDING_RETURN);
        // Assert
        assertEquals(
                2,
                (vcs.stream()
                        .filter(
                                vc ->
                                        vc.getCri().equals(Cri.ADDRESS)
                                                || vc.getCri().equals(Cri.DCMAW))
                        .count()));
    }

    @Test
    void storeInheritedIdentityShouldStoreCurrentVc() throws Exception {
        var inheritedId = vcHmrcMigrationPCL200();

        evcsService.storeInheritedIdentity(TEST_USER_ID, inheritedId, List.of());

        verify(mockEvcsClient)
                .storeUserVCs(eq(TEST_USER_ID), evcsCreateUserVCsDtosCaptor.capture());

        var createDto = evcsCreateUserVCsDtosCaptor.getValue().get(0);
        assertEquals(inheritedId.getVcString(), createDto.vc());
        assertEquals(CURRENT, createDto.state());
    }

    @Test
    void storeInheritedIdentityShouldMoveExistingIdentitiesToHistoric() throws Exception {
        var existingInheritedIds =
                List.of(vcHmrcMigrationPCL200(), vcHmrcMigrationPCL200NoEvidence());
        var incomingInheritedId = vcHmrcMigrationPCL250();

        evcsService.storeInheritedIdentity(TEST_USER_ID, incomingInheritedId, existingInheritedIds);

        verify(mockEvcsClient)
                .updateUserVCs(eq(TEST_USER_ID), evcsUpdateUserVCsDtosCaptor.capture());
        verify(mockEvcsClient)
                .storeUserVCs(eq(TEST_USER_ID), evcsCreateUserVCsDtosCaptor.capture());

        var updateDtos = evcsUpdateUserVCsDtosCaptor.getValue();

        assertEquals(
                existingInheritedIds.get(0).getSignedJwt().getSignature().toString(),
                updateDtos.get(0).signature());
        assertEquals(HISTORIC, updateDtos.get(0).state());

        assertEquals(
                existingInheritedIds.get(1).getSignedJwt().getSignature().toString(),
                updateDtos.get(1).signature());
        assertEquals(HISTORIC, updateDtos.get(1).state());

        var createDto = evcsCreateUserVCsDtosCaptor.getValue().get(0);
        assertEquals(incomingInheritedId.getVcString(), createDto.vc());
        assertEquals(CURRENT, createDto.state());
    }

    @Test
    void storeInheritedIdentityShouldThrowIfFailsToCreate() throws Exception {
        doThrow(new EvcsServiceException(SC_SERVER_ERROR, FAILED_TO_CONSTRUCT_EVCS_URI))
                .when(mockEvcsClient)
                .storeUserVCs(any(), any());

        var evcsServiceException =
                assertThrows(
                        EvcsServiceException.class,
                        () ->
                                evcsService.storeInheritedIdentity(
                                        TEST_USER_ID, vcHmrcMigrationPCL200(), List.of()));

        assertEquals(FAILED_TO_CONSTRUCT_EVCS_URI, evcsServiceException.getErrorResponse());
    }

    @Test
    void storeInheritedIdentityShouldThrowIfFailsToUpdate() throws Exception {
        doThrow(new EvcsServiceException(SC_SERVER_ERROR, FAILED_TO_PARSE_EVCS_REQUEST_BODY))
                .when(mockEvcsClient)
                .updateUserVCs(any(), any());

        var evcsServiceException =
                assertThrows(
                        EvcsServiceException.class,
                        () ->
                                evcsService.storeInheritedIdentity(
                                        TEST_USER_ID,
                                        vcHmrcMigrationPCL200(),
                                        List.of(vcHmrcMigrationPCL250())));

        assertEquals(FAILED_TO_PARSE_EVCS_REQUEST_BODY, evcsServiceException.getErrorResponse());
    }
}
