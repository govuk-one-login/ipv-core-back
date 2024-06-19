package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.client.EvcsClient;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.dto.EvcsGetUserVCDto;
import uk.gov.di.ipv.core.library.dto.EvcsGetUserVCsDto;
import uk.gov.di.ipv.core.library.dto.EvcsUpdateUserVCsDto;
import uk.gov.di.ipv.core.library.enums.EvcsVCState;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.NoCriForIssuerException;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.VC_ADDRESS;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermit;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermitNonDcmaw;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fM1a;

@ExtendWith(MockitoExtension.class)
class EvcsServiceTest {
    private static final VerifiableCredential VC_DRIVING_PERMIT_TEST = vcDrivingPermit();
    private static final VerifiableCredential VC_ADDRESS_TEST = VC_ADDRESS;
    private static final VerifiableCredential VC_PASSPORT_NON_DCMAW_SUCCESSFUL_TEST =
            PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
    private static final VerifiableCredential VC_F2F = vcF2fM1a();
    private static final List<VerifiableCredential> VERIFIABLE_CREDENTIALS =
            List.of(VC_DRIVING_PERMIT_TEST, VC_ADDRESS_TEST, M1A_EXPERIAN_FRAUD_VC);
    private static final List<VerifiableCredential> VERIFIABLE_CREDENTIALS_ONE_EXIST_IN_EVCS =
            List.of(
                    VC_DRIVING_PERMIT_TEST,
                    VC_ADDRESS_TEST,
                    M1A_EXPERIAN_FRAUD_VC,
                    VC_PASSPORT_NON_DCMAW_SUCCESSFUL_TEST);
    private static final List<VerifiableCredential> VERIFIABLE_CREDENTIALS_ALL_EXIST_IN_EVCS =
            List.of(VC_DRIVING_PERMIT_TEST, VC_ADDRESS_TEST, VC_F2F);
    private static final String TEST_USER_ID = "a-user-id";
    private static final List<EvcsVCState> VC_STATES_TO_QUERY_FOR =
            List.of(CURRENT, PENDING_RETURN);

    private static final String TEST_EVCS_ACCESS_TOKEN = "TEST_EVCS_ACCESS_TOKEN";
    private static final EvcsGetUserVCsDto EVCS_GET_USER_VCS_DTO =
            new EvcsGetUserVCsDto(
                    List.of(
                            new EvcsGetUserVCDto(
                                    vcAddressTwo().getVcString(),
                                    EvcsVCState.CURRENT,
                                    Map.of(
                                            "reason", "testing",
                                            "txmaEventId", "txma-event-id-2",
                                            "timestampMs", "1714478033959")),
                            new EvcsGetUserVCDto(
                                    vcDrivingPermitNonDcmaw().getVcString(),
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
                                            "timestampMs", "1714478033959"))));

    @Captor ArgumentCaptor<List<EvcsCreateUserVCsDto>> evcsCreateUserVCsDtosCaptor;
    @Captor ArgumentCaptor<List<EvcsUpdateUserVCsDto>> evcsUpdateUserVCsDtosCaptor;
    @Captor ArgumentCaptor<String> stringArgumentCaptor;

    @Mock EvcsClient mockEvcsClient;
    @Mock ConfigService mockConfigService;
    @InjectMocks EvcsService evcsService;

    @Test
    void testStoreIdentity_whenNoExistingEvcsUserVCs() throws Exception {
        // Arrange
        when(mockEvcsClient.getUserVcs(
                        TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_TO_QUERY_FOR))
                .thenReturn(new EvcsGetUserVCsDto(Collections.emptyList()));
        // Act
        evcsService.storeCompletedIdentity(
                TEST_USER_ID, VERIFIABLE_CREDENTIALS, TEST_EVCS_ACCESS_TOKEN);
        // Assert
        InOrder mockOrderVerifier = Mockito.inOrder(mockEvcsClient);
        mockOrderVerifier
                .verify(mockEvcsClient)
                .getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_TO_QUERY_FOR);
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
    }

    @Test
    void testStorePendingIdentity_onSuccessfulJourney_for_incompleteF2F() throws Exception {
        // Arrange
        when(mockEvcsClient.getUserVcs(
                        TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_TO_QUERY_FOR))
                .thenReturn(new EvcsGetUserVCsDto(Collections.emptyList()));
        // Act
        evcsService.storePendingIdentity(
                TEST_USER_ID, VERIFIABLE_CREDENTIALS_ONE_EXIST_IN_EVCS, TEST_EVCS_ACCESS_TOKEN);
        // Assert
        InOrder mockOrderVerifier = Mockito.inOrder(mockEvcsClient);
        mockOrderVerifier
                .verify(mockEvcsClient)
                .getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_TO_QUERY_FOR);
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
        // Arrange
        when(mockEvcsClient.getUserVcs(
                        TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_TO_QUERY_FOR))
                .thenReturn(EVCS_GET_USER_VCS_DTO);
        // Act
        evcsService.storeCompletedIdentity(
                TEST_USER_ID, VERIFIABLE_CREDENTIALS_ONE_EXIST_IN_EVCS, TEST_EVCS_ACCESS_TOKEN);
        // Assert
        InOrder mockOrderVerifier = Mockito.inOrder(mockEvcsClient);
        mockOrderVerifier
                .verify(mockEvcsClient)
                .getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_TO_QUERY_FOR);
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
        EvcsGetUserVCsDto EVCS_GET_USER_VCS_WITH_ALL_EXISTING_DTO =
                new EvcsGetUserVCsDto(
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
                                        Map.of("reason", "testing"))));
        when(mockEvcsClient.getUserVcs(
                        TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_TO_QUERY_FOR))
                .thenReturn(EVCS_GET_USER_VCS_WITH_ALL_EXISTING_DTO);
        // Act
        evcsService.storeCompletedIdentity(
                TEST_USER_ID, VERIFIABLE_CREDENTIALS_ALL_EXIST_IN_EVCS, TEST_EVCS_ACCESS_TOKEN);
        // Assert
        InOrder mockOrderVerifier = Mockito.inOrder(mockEvcsClient);
        mockOrderVerifier
                .verify(mockEvcsClient)
                .getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_TO_QUERY_FOR);
        mockOrderVerifier.verify(mockEvcsClient, times(0)).updateUserVCs(any(), any());
        mockOrderVerifier.verify(mockEvcsClient, times(0)).storeUserVCs(any(), any());
    }

    @Test
    void testStoreCompleteIdentity_whenAllVCsExistInEvcs_inSession_withPendingReturnState()
            throws Exception {
        // Arrange
        EvcsGetUserVCsDto EVCS_GET_USER_VCS_WITH_ALL_EXISTING_DTO =
                new EvcsGetUserVCsDto(
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
                                        Map.of("reason", "testing"))));
        when(mockEvcsClient.getUserVcs(
                        TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_TO_QUERY_FOR))
                .thenReturn(EVCS_GET_USER_VCS_WITH_ALL_EXISTING_DTO);
        // Act
        evcsService.storeCompletedIdentity(
                TEST_USER_ID, VERIFIABLE_CREDENTIALS_ALL_EXIST_IN_EVCS, TEST_EVCS_ACCESS_TOKEN);
        // Assert
        InOrder mockOrderVerifier = Mockito.inOrder(mockEvcsClient);
        mockOrderVerifier
                .verify(mockEvcsClient)
                .getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_TO_QUERY_FOR);
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
        EvcsGetUserVCsDto EVCS_GET_USER_VCS_WITH_ALL_EXISTING_DTO =
                new EvcsGetUserVCsDto(
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
                                        Map.of("reason", "testing"))));
        when(mockEvcsClient.getUserVcs(
                        TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_TO_QUERY_FOR))
                .thenReturn(EVCS_GET_USER_VCS_WITH_ALL_EXISTING_DTO);
        // Act
        evcsService.storeCompletedIdentity(
                TEST_USER_ID, Collections.emptyList(), TEST_EVCS_ACCESS_TOKEN);
        // Assert
        InOrder mockOrderVerifier = Mockito.inOrder(mockEvcsClient);
        mockOrderVerifier
                .verify(mockEvcsClient)
                .getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_TO_QUERY_FOR);
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
    void storeAsyncVcShouldStoreVcWithPendingReturnState() throws EvcsServiceException {
        evcsService.storePendingVc(VC_ADDRESS_TEST);

        verify(mockEvcsClient)
                .storeUserVCs(
                        stringArgumentCaptor.capture(), evcsCreateUserVCsDtosCaptor.capture());

        assertEquals(VC_ADDRESS_TEST.getUserId(), stringArgumentCaptor.getValue());
        assertEquals(
                VC_ADDRESS_TEST.getVcString(), evcsCreateUserVCsDtosCaptor.getValue().get(0).vc());
        assertEquals(PENDING_RETURN, evcsCreateUserVCsDtosCaptor.getValue().get(0).state());
    }

    @Test
    void testGetVerifiableCredentials()
            throws CredentialParseException, NoCriForIssuerException, EvcsServiceException {
        // Arrange
        when(mockConfigService.getCriByIssuer(M1A_ADDRESS_VC.getClaimsSet().getIssuer()))
                .thenReturn(Cri.ADDRESS);
        when(mockConfigService.getCriByIssuer(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getClaimsSet().getIssuer()))
                .thenReturn(Cri.DCMAW);

        when(mockEvcsClient.getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, List.of(CURRENT)))
                .thenReturn(
                        new EvcsGetUserVCsDto(
                                List.of(
                                        new EvcsGetUserVCDto(
                                                M1A_ADDRESS_VC.getVcString(),
                                                EvcsVCState.CURRENT,
                                                null),
                                        new EvcsGetUserVCDto(
                                                PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(),
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
                                        vc.getCriId().equals(Cri.ADDRESS.getId())
                                                || vc.getCriId().equals(Cri.DCMAW.getId()))
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
                                                M1A_EXPERIAN_FRAUD_VC.getVcString(),
                                                EvcsVCState.CURRENT,
                                                null),
                                        new EvcsGetUserVCDto(
                                                PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(),
                                                EvcsVCState.CURRENT,
                                                null))));

        // Act/Assert
        assertThrows(
                CredentialParseException.class,
                () -> {
                    evcsService.getVerifiableCredentials(
                            TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, CURRENT);
                });
    }
}
