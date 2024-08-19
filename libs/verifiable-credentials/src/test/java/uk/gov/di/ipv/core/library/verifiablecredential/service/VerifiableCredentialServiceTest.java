package uk.gov.di.ipv.core.library.verifiablecredential.service;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.BatchProcessingException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;

import java.util.List;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_DELETE_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_STORE_IDENTITY;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_UPDATE_IDENTITY;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.EXPIRED_M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.TEST_SUBJECT;

@ExtendWith(MockitoExtension.class)
class VerifiableCredentialServiceTest {
    private static final String USER_ID = "user-id";
    @Captor ArgumentCaptor<VcStoreItem> vcStoreItemCaptor;
    @Mock private DataStore<VcStoreItem> mockDataStore;
    @InjectMocks private VerifiableCredentialService verifiableCredentialService;

    @Test
    void expectedSuccessWhenSaveCredentials() throws Exception {
        ArgumentCaptor<VcStoreItem> userIssuedCredentialsItemCaptor =
                ArgumentCaptor.forClass(VcStoreItem.class);

        verifiableCredentialService.persistUserCredentials(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);
        verify(mockDataStore).create(userIssuedCredentialsItemCaptor.capture());
        VcStoreItem vcStoreItem = userIssuedCredentialsItemCaptor.getValue();

        assertEquals(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getUserId(), vcStoreItem.getUserId());
        assertEquals(
                PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getCri().getId(),
                vcStoreItem.getCredentialIssuer());
        assertEquals(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(), vcStoreItem.getCredential());
    }

    @Test
    void expectedExceptionWhenSaveCredentials() {
        doThrow(new UnsupportedOperationException()).when(mockDataStore).create(any(), any());

        VerifiableCredentialException thrown =
                assertThrows(
                        VerifiableCredentialException.class,
                        () ->
                                verifiableCredentialService.persistUserCredentials(
                                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC));

        assertNotNull(thrown);
        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getResponseCode());
        assertEquals(ErrorResponse.FAILED_TO_SAVE_CREDENTIAL, thrown.getErrorResponse());
    }

    @Test
    void shouldReturnCredentialIssuersFromDataStoreForSpecificUserId()
            throws CredentialParseException {
        var userId = PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getUserId();
        var testCredentialIssuer = PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getCri();
        var credentialItem = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.toVcStoreItem());

        when(mockDataStore.getItems(userId)).thenReturn(credentialItem);

        var vcs = verifiableCredentialService.getVcs(userId);

        assertTrue(
                vcs.stream()
                        .map(VerifiableCredential::getCri)
                        .anyMatch(testCredentialIssuer::equals));
    }

    @Test
    void shouldReturnCredentialFromDataStoreForSpecificCri() throws CredentialParseException {
        var ipvSessionId = "ipvSessionId";
        var cri = PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getCri();

        when(mockDataStore.getItem(ipvSessionId, cri.getId()))
                .thenReturn(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.toVcStoreItem());

        var retrievedCredentialItem = verifiableCredentialService.getVc(ipvSessionId, cri.getId());

        assertEquals(
                PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getUserId(), retrievedCredentialItem.getUserId());
        assertEquals(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getCri(), retrievedCredentialItem.getCri());
        assertEquals(
                PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(),
                retrievedCredentialItem.getVcString());
    }

    @Test
    void shouldDeleteAllExistingVCsForPartitionKeyUserId() throws Exception {
        verifiableCredentialService.deleteVCs(TEST_SUBJECT);

        ArgumentCaptor<String> userIdCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockDataStore).deleteAllByPartition(userIdCaptor.capture());
        assertEquals(TEST_SUBJECT, userIdCaptor.getValue());
    }

    @Test
    void storeIdentityShouldClearVcsAndStoreNewOnes() throws Exception {
        var vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        EXPIRED_M1A_EXPERIAN_FRAUD_VC,
                        M1A_ADDRESS_VC);

        verifiableCredentialService.storeIdentity(vcs, USER_ID);

        var inOrder = inOrder(mockDataStore);
        inOrder.verify(mockDataStore).deleteAllByPartition(USER_ID);
        inOrder.verify(mockDataStore, times(3)).create(vcStoreItemCaptor.capture());
        inOrder.verifyNoMoreInteractions();

        var capturedItems = vcStoreItemCaptor.getAllValues();

        assertEquals(
                PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(),
                capturedItems.get(0).getCredential());
        assertEquals(
                EXPIRED_M1A_EXPERIAN_FRAUD_VC.getVcString(), capturedItems.get(1).getCredential());
        assertEquals(M1A_ADDRESS_VC.getVcString(), capturedItems.get(2).getCredential());
    }

    @Test
    void storeIdentityShouldThrowIfFailureToDeleteExistingVc() throws Exception {
        doThrow(new BatchProcessingException("Deletion failed"))
                .when(mockDataStore)
                .deleteAllByPartition(USER_ID);

        var verifiableCredentialException =
                assertThrows(
                        VerifiableCredentialException.class,
                        () -> verifiableCredentialService.storeIdentity(List.of(), USER_ID));

        assertEquals(SC_SERVER_ERROR, verifiableCredentialException.getResponseCode());
        assertEquals(FAILED_TO_DELETE_CREDENTIAL, verifiableCredentialException.getErrorResponse());
    }

    @Test
    void storeIdentityShouldThrowIfAnyFailure() {
        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);
        doThrow(new IllegalStateException()).when(mockDataStore).create(any());

        var verifiableCredentialException =
                assertThrows(
                        VerifiableCredentialException.class,
                        () -> verifiableCredentialService.storeIdentity(vcs, USER_ID));

        assertEquals(SC_SERVER_ERROR, verifiableCredentialException.getResponseCode());
        assertEquals(FAILED_TO_STORE_IDENTITY, verifiableCredentialException.getErrorResponse());
    }

    @Test
    void updateIdentityShouldClearVcsAndStoreNewOnes() throws Exception {
        var vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        EXPIRED_M1A_EXPERIAN_FRAUD_VC,
                        M1A_ADDRESS_VC);

        verifiableCredentialService.updateIdentity(vcs);

        verify(mockDataStore, times(3)).update(vcStoreItemCaptor.capture());

        var capturedItems = vcStoreItemCaptor.getAllValues();

        assertEquals(
                PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(),
                capturedItems.get(0).getCredential());
        assertEquals(
                EXPIRED_M1A_EXPERIAN_FRAUD_VC.getVcString(), capturedItems.get(1).getCredential());
        assertEquals(M1A_ADDRESS_VC.getVcString(), capturedItems.get(2).getCredential());
    }

    @Test
    void updateIdentityShouldThrowExceptionOnUpdate() {
        var vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        EXPIRED_M1A_EXPERIAN_FRAUD_VC,
                        M1A_ADDRESS_VC);
        doThrow(new IllegalStateException()).when(mockDataStore).update(any());

        var verifiableCredentialException =
                assertThrows(
                        VerifiableCredentialException.class,
                        () -> verifiableCredentialService.updateIdentity(vcs));

        assertEquals(SC_SERVER_ERROR, verifiableCredentialException.getResponseCode());
        assertEquals(FAILED_TO_UPDATE_IDENTITY, verifiableCredentialException.getErrorResponse());
    }

    @Test
    void storeIdentityShouldThrowIfFailureToWriteNewVc() {
        doThrow(new IllegalStateException()).when(mockDataStore).create(any());

        var verifiableCredentialException =
                assertThrows(
                        VerifiableCredentialException.class,
                        () ->
                                verifiableCredentialService.storeIdentity(
                                        List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC), USER_ID));

        assertEquals(SC_SERVER_ERROR, verifiableCredentialException.getResponseCode());
        assertEquals(FAILED_TO_STORE_IDENTITY, verifiableCredentialException.getErrorResponse());
    }
}
