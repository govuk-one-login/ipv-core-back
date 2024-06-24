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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.HMRC_MIGRATION;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_STORE_IDENTITY;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_UPDATE_IDENTITY;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.EXPIRED_M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudScoreOne;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudScoreTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL250NoEvidence;

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
                PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getCriId(), vcStoreItem.getCredentialIssuer());
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
        var testCredentialIssuer = PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getCriId();
        var credentialItem = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.toVcStoreItem());

        when(mockDataStore.getItems(userId)).thenReturn(credentialItem);

        var vcs = verifiableCredentialService.getVcs(userId);

        assertTrue(
                vcs.stream()
                        .map(VerifiableCredential::getCriId)
                        .anyMatch(testCredentialIssuer::equals));
    }

    @Test
    void shouldReturnCredentialFromDataStoreForSpecificCri() throws CredentialParseException {
        var ipvSessionId = "ipvSessionId";
        var criId = PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getCriId();

        when(mockDataStore.getItem(ipvSessionId, criId))
                .thenReturn(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.toVcStoreItem());

        var retrievedCredentialItem = verifiableCredentialService.getVc(ipvSessionId, criId);

        assertEquals(
                PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getUserId(), retrievedCredentialItem.getUserId());
        assertEquals(
                PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getCriId(), retrievedCredentialItem.getCriId());
        assertEquals(
                PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(),
                retrievedCredentialItem.getVcString());
    }

    @Test
    void shouldDeleteAllExistingVCs() {
        var experianVc1 = vcExperianFraudScoreOne();
        var experianVc2 = vcExperianFraudScoreTwo();
        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, experianVc1, experianVc2);

        verifiableCredentialService.deleteVcs(vcs, true);

        verify(mockDataStore)
                .delete(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getUserId(),
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getCriId());
        verify(mockDataStore).delete(experianVc1.getUserId(), experianVc1.getCriId());
        verify(mockDataStore).delete(experianVc2.getUserId(), experianVc2.getCriId());
    }

    @Test
    void shouldDeleteInheritedIdentityIfPresent() throws Exception {
        // Arrange
        var inheritedIdentityVc = vcHmrcMigrationPCL250NoEvidence();
        var vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        vcExperianFraudScoreOne(),
                        vcExperianFraudScoreTwo(),
                        inheritedIdentityVc);

        // Act
        verifiableCredentialService.deleteHmrcInheritedIdentityIfPresent(vcs);

        // Assert
        verify(mockDataStore, times(1))
                .delete(inheritedIdentityVc.getUserId(), inheritedIdentityVc.getCriId());
    }

    @Test
    void shouldNotDeleteInheritedIdentityIfNotPresent() {
        // Arrange
        var vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        vcExperianFraudScoreOne(),
                        vcExperianFraudScoreTwo());

        // Act
        verifiableCredentialService.deleteHmrcInheritedIdentityIfPresent(vcs);

        // Assert
        verify(mockDataStore, times(0)).delete(any(), eq(HMRC_MIGRATION.getId()));
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
    void storeIdentityShouldThrowIfFailureToDeleteExistingVc() {
        doThrow(new IllegalStateException()).when(mockDataStore).deleteAllByPartition(USER_ID);

        var verifiableCredentialException =
                assertThrows(
                        VerifiableCredentialException.class,
                        () -> verifiableCredentialService.storeIdentity(List.of(), USER_ID));

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
