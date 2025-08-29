package uk.gov.di.ipv.core.library.evcs.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.client.EvcsClient;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsGetUserVCDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsGetUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsPostIdentityDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsStoredIdentityDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsUpdateUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.enums.Vot.P1;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVcProvenance.OFFLINE;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVcProvenance.ONLINE;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressOne;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fPassportPhotoM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcSecurityCheckNoCis;
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
    @Captor ArgumentCaptor<EvcsPostIdentityDto> evcsPostIdentityDtoCaptor;
    @Captor ArgumentCaptor<String> stringArgumentCaptor;

    @Mock EvcsClient mockEvcsClient;
    @Mock ConfigService mockConfigService;
    @Mock StoredIdentityService mockStoredIdentityService;
    @InjectMocks EvcsService evcsService;

    @BeforeEach
    void setUp() {
        clientOAuthSessionItem = ClientOAuthSessionItem.builder().userId(TEST_USER_ID).build();
    }

    @Nested
    class StoreIdentityWithPost {
        @Test
        void testStoreIdentity_whenNoExistingEvcsUserVCs() throws Exception {
            // Act
            evcsService.storeCompletedOrPendingIdentityWithPostVcs(
                    TEST_USER_ID, VERIFIABLE_CREDENTIALS, List.of(), false);

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
                    userVCsForEvcs.stream()
                            .anyMatch(dto -> !dto.state().equals(EvcsVCState.CURRENT)));
            assertFalse(userVCsForEvcs.stream().anyMatch(dto -> !dto.provenance().equals(ONLINE)));
        }

        @Test
        void testStorePendingIdentity_onSuccessfulJourney_for_incompleteF2F() throws Exception {
            // Act
            evcsService.storeCompletedOrPendingIdentityWithPostVcs(
                    TEST_USER_ID, VERIFIABLE_CREDENTIALS_ONE_EXIST_IN_EVCS, List.of(), true);

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
        void testStoreIdentity_for_6MFCJourney() throws Exception {
            // Act
            evcsService.storeCompletedOrPendingIdentityWithPostVcs(
                    TEST_USER_ID,
                    VERIFIABLE_CREDENTIALS_ONE_EXIST_IN_EVCS,
                    EVCS_GET_USER_VC_DTO,
                    false);

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
            evcsService.storeCompletedOrPendingIdentityWithPostVcs(
                    TEST_USER_ID,
                    VERIFIABLE_CREDENTIALS_ALL_EXIST_IN_EVCS,
                    evcsGetUserVcsWithCurrentStateAllExistingDto,
                    false);

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
            evcsService.storeCompletedOrPendingIdentityWithPostVcs(
                    TEST_USER_ID,
                    VERIFIABLE_CREDENTIALS_ALL_EXIST_IN_EVCS,
                    evcsGetUserVcsWithPendingAllExistingDto,
                    false);

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
            evcsService.storeCompletedOrPendingIdentityWithPostVcs(
                    TEST_USER_ID, List.of(), evcsGetUserVcsWithPendingAllExistingDto, false);

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
    }

    @Nested
    class StoreIdentityWithPostIdentityMethod {
        @Test
        void shouldStorePendingIdentityWithPostIdentityMethod() throws Exception {
            // Arrange
            var testVcs = List.of(VC_ADDRESS_TEST);

            // Act
            evcsService.storePendingIdentityWithPostIdentity(TEST_USER_ID, testVcs);

            // Assert
            verify(mockEvcsClient).storeUserIdentity(evcsPostIdentityDtoCaptor.capture());

            assertEquals(
                    clientOAuthSessionItem.getUserId(),
                    evcsPostIdentityDtoCaptor.getValue().userId());
            assertEquals(
                    VC_ADDRESS_TEST.getVcString(),
                    evcsPostIdentityDtoCaptor.getValue().vcs().get(0).vc());
            assertEquals(PENDING_RETURN, evcsPostIdentityDtoCaptor.getValue().vcs().get(0).state());
            assertEquals(ONLINE, evcsPostIdentityDtoCaptor.getValue().vcs().get(0).provenance());

            verify(mockEvcsClient, never()).updateUserVCs(any(), any());
            verify(mockEvcsClient, never()).storeUserVCs(any(), any());
        }

        @Test
        void shouldStoreCompletedIdentityWithPostIdentityMethod() throws Exception {
            // Arrange
            var testVcs = List.of(VC_ADDRESS_TEST);
            var testSiJwt = "test.si.jwt";
            when(mockStoredIdentityService.getStoredIdentityForEvcs(
                            TEST_USER_ID, testVcs, STRONGEST_MATCHED_VOT, ACHIEVED_VOT))
                    .thenReturn(new EvcsStoredIdentityDto(testSiJwt, P1));

            // Act
            evcsService.storeCompletedIdentityWithPostIdentity(
                    TEST_USER_ID, testVcs, STRONGEST_MATCHED_VOT, ACHIEVED_VOT);

            // Assert
            verify(mockEvcsClient).storeUserIdentity(evcsPostIdentityDtoCaptor.capture());

            assertEquals(
                    clientOAuthSessionItem.getUserId(),
                    evcsPostIdentityDtoCaptor.getValue().userId());
            assertEquals(
                    VC_ADDRESS_TEST.getVcString(),
                    evcsPostIdentityDtoCaptor.getValue().vcs().get(0).vc());
            assertEquals(CURRENT, evcsPostIdentityDtoCaptor.getValue().vcs().get(0).state());
            assertEquals(ONLINE, evcsPostIdentityDtoCaptor.getValue().vcs().get(0).provenance());
            assertEquals(testSiJwt, evcsPostIdentityDtoCaptor.getValue().si().jwt());
            assertEquals(P1, evcsPostIdentityDtoCaptor.getValue().si().vot());

            verify(mockEvcsClient, never()).updateUserVCs(any(), any());
            verify(mockEvcsClient, never()).storeUserVCs(any(), any());
        }
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
                                        Map.of("reason", "testing"))),
                        null);
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
    void testGetVerifiableCredentials() throws CredentialParseException, EvcsServiceException {
        // Arrange
        when(mockConfigService.getIssuerCris())
                .thenReturn(
                        Map.of(
                                vcAddressM1a().getClaimsSet().getIssuer(),
                                Cri.ADDRESS,
                                vcWebPassportSuccessful().getClaimsSet().getIssuer(),
                                Cri.DCMAW));
        when(mockConfigService.getParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn("https://cimit.stubs.account.gov.uk");

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
                                                null)),
                                null));

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
    void testGetVerifiableCredentialsShouldErrorWhenCriNotFound() throws EvcsServiceException {
        // Arrange
        when(mockConfigService.getIssuerCris()).thenReturn(Map.of());

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
                                                null)),
                                null));
        when(mockConfigService.getParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn("https://cimit.stubs.account.gov.uk");

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

        when(mockConfigService.getIssuerCris())
                .thenReturn(
                        Map.of(
                                vcAddressM1a().getClaimsSet().getIssuer(),
                                Cri.ADDRESS,
                                vcWebPassportSuccessful().getClaimsSet().getIssuer(),
                                Cri.DCMAW));
        when(mockConfigService.getParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn("https://cimit.stubs.account.gov.uk");

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

        when(mockConfigService.getIssuerCris())
                .thenReturn(
                        Map.of(
                                vcAddressM1a().getClaimsSet().getIssuer(),
                                Cri.ADDRESS,
                                vcWebPassportSuccessful().getClaimsSet().getIssuer(),
                                Cri.DCMAW));
        when(mockConfigService.getParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn("https://cimit.stubs.account.gov.uk");

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
    void getVerifiableCredentialsFiltersOutCimitVcs() throws Exception {
        // Arrange
        var evcsVcs =
                List.of(
                        new EvcsGetUserVCDto(vcAddressM1a().getVcString(), CURRENT, null),
                        new EvcsGetUserVCDto(
                                vcWebPassportSuccessful().getVcString(), CURRENT, null),
                        new EvcsGetUserVCDto(vcSecurityCheckNoCis().getVcString(), CURRENT, null));

        when(mockConfigService.getIssuerCris())
                .thenReturn(
                        Map.of(
                                vcAddressM1a().getClaimsSet().getIssuer(),
                                Cri.ADDRESS,
                                vcWebPassportSuccessful().getClaimsSet().getIssuer(),
                                Cri.DCMAW));
        when(mockConfigService.getParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn("https://cimit.stubs.account.gov.uk");

        // Act
        var vcs = evcsService.getVerifiableCredentials(TEST_USER_ID, evcsVcs, CURRENT);
        // Assert
        assertEquals(2, vcs.size());
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
    void shouldStoreStoredIdentityRecord() throws Exception {
        // Arrange
        var testVcs = List.of(VC_ADDRESS_TEST);
        var testSiJwt = "test.si.jwt";

        when(mockStoredIdentityService.getStoredIdentityForEvcs(
                        TEST_USER_ID, testVcs, STRONGEST_MATCHED_VOT, ACHIEVED_VOT))
                .thenReturn(new EvcsStoredIdentityDto(testSiJwt, P1));

        // Act
        evcsService.storeStoredIdentityRecord(
                TEST_USER_ID, testVcs, STRONGEST_MATCHED_VOT, ACHIEVED_VOT);

        // Assert
        verify(mockEvcsClient).storeUserIdentity(evcsPostIdentityDtoCaptor.capture());

        assertEquals(testSiJwt, evcsPostIdentityDtoCaptor.getValue().si().jwt());
        assertEquals(P1, evcsPostIdentityDtoCaptor.getValue().si().vot());

        verify(mockEvcsClient, never()).updateUserVCs(any(), any());
        verify(mockEvcsClient, never()).storeUserVCs(any(), any());
    }

    @Test
    void shouldInvalidateStoredIdentityRecord() throws Exception {
        // Act
        evcsService.invalidateStoredIdentityRecord(TEST_USER_ID);

        // Assert
        verify(mockEvcsClient, times(1)).invalidateStoredIdentityRecord(TEST_USER_ID);
    }
}
