package uk.gov.di.ipv.core.library.verifiablecredential.service;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.HMRC_MIGRATION_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudScoreOne;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudScoreTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL250NoEvidence;

@WireMockTest
@ExtendWith(MockitoExtension.class)
class VerifiableCredentialServiceTest {
    @Mock private DataStore<VcStoreItem> mockDataStore;
    @Mock private ConfigService mockConfigService;
    private VerifiableCredentialService verifiableCredentialService;

    @BeforeEach
    void setUp() {
        verifiableCredentialService =
                new VerifiableCredentialService(mockDataStore, mockConfigService);
    }

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
    void expectedSuccessWithoutExpWhenSaveCredentials() throws Exception {
        String credentialIssuerId = "cred_issuer_id_1";
        String userId = "user-id-1";
        SignedJWT signedJwt =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).build(),
                        new JWTClaimsSet.Builder()
                                .subject("testSubject")
                                .issuer(credentialIssuerId)
                                .build());
        signedJwt.sign(new ECDSASigner(getPrivateKey()));
        var vc = VerifiableCredential.fromValidJwt(userId, credentialIssuerId, signedJwt);

        ArgumentCaptor<VcStoreItem> userIssuedCredentialsItemCaptor =
                ArgumentCaptor.forClass(VcStoreItem.class);

        verifiableCredentialService.persistUserCredentials(vc);

        verify(mockDataStore).create(userIssuedCredentialsItemCaptor.capture());
        VcStoreItem vcStoreItem = userIssuedCredentialsItemCaptor.getValue();

        assertNull(vcStoreItem.getExpirationTime());
        assertEquals(userId, vcStoreItem.getUserId());
        assertEquals(credentialIssuerId, vcStoreItem.getCredentialIssuer());
        assertEquals(signedJwt.serialize(), vcStoreItem.getCredential());
    }

    @Test
    void expectedExceptionWhenSaveCredentials() throws Exception {
        doThrow(new UnsupportedOperationException()).when(mockDataStore).create(any(), any());

        VerifiableCredentialException thrown =
                assertThrows(
                        VerifiableCredentialException.class,
                        () ->
                                verifiableCredentialService.persistUserCredentials(
                                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC));

        assertNotNull(thrown);
        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
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
    void shouldDeleteAllExistingVCs() throws CredentialParseException {
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
        verify(mockDataStore, times(0)).delete(any(), eq(HMRC_MIGRATION_CRI));
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }
}
