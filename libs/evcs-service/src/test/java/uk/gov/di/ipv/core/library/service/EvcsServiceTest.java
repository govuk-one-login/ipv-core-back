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
import uk.gov.di.ipv.core.library.domain.CriIdentifer;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.dto.EvcsGetUserVCDto;
import uk.gov.di.ipv.core.library.dto.EvcsGetUserVCsDto;
import uk.gov.di.ipv.core.library.dto.EvcsUpdateUserVCsDto;
import uk.gov.di.ipv.core.library.enums.EvcsVCState;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;

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

@ExtendWith(MockitoExtension.class)
class EvcsServiceTest {
    private static final List<VerifiableCredential> VERIFIABLE_CREDENTIALS =
            List.of(vcDrivingPermit(), VC_ADDRESS, M1A_EXPERIAN_FRAUD_VC);
    private static final List<VerifiableCredential> VERIFIABLE_CREDENTIALS_ONE_EXIST_IN_EVCS =
            List.of(
                    vcDrivingPermit(),
                    VC_ADDRESS,
                    M1A_EXPERIAN_FRAUD_VC,
                    PASSPORT_NON_DCMAW_SUCCESSFUL_VC);
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
                                    PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(),
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
    void testStoreIdentity_whenNoExistingEvcsUserVCs() {
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
    void testStorePendingIdentity_onSuccessfulJourney_for_incompleteF2F() {
        // Arrange
        when(mockEvcsClient.getUserVcs(
                        TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_TO_QUERY_FOR))
                .thenReturn(EVCS_GET_USER_VCS_DTO);
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
    void testStoreIdentity_for_6MFCJourney() {
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
    void storeAsyncVcShouldStoreVcWithPendingReturnState() {
        evcsService.storePendingVc(VC_ADDRESS);

        verify(mockEvcsClient)
                .storeUserVCs(
                        stringArgumentCaptor.capture(), evcsCreateUserVCsDtosCaptor.capture());

        assertEquals(VC_ADDRESS.getUserId(), stringArgumentCaptor.getValue());
        assertEquals(VC_ADDRESS.getVcString(), evcsCreateUserVCsDtosCaptor.getValue().get(0).vc());
        assertEquals(PENDING_RETURN, evcsCreateUserVCsDtosCaptor.getValue().get(0).state());
    }

    @Test
    void testGetVerifiableCredentials() throws CredentialParseException {
        // Arrange
        when(mockConfigService.getCriConfigs())
                .thenReturn(
                        Map.of(
                                M1A_ADDRESS_VC.getClaimsSet().getIssuer(),
                                CriIdentifer.ADDRESS.getId(),
                                PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getClaimsSet().getIssuer(),
                                CriIdentifer.DCMAW.getId()));

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
                                        vc.getCriId().equals(CriIdentifer.ADDRESS.getId())
                                                || vc.getCriId().equals(CriIdentifer.DCMAW.getId()))
                        .count()));
    }

    @Test
    void testGetVerifiableCredentialsShouldErrorWhenCriNotFound() {
        // Arrange
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
