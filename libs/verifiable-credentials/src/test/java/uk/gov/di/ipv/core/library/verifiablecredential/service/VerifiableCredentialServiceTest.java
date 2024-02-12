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
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.CredentialAlreadyExistsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.EXPERIAN_FRAUD_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.PASSPORT_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_EXPERIAN_FRAUD_SCORE_1;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_EXPERIAN_KBV_SCORE_2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_PASSPORT_NON_DCMAW_SUCCESSFUL;

@WireMockTest
@ExtendWith(MockitoExtension.class)
class VerifiableCredentialServiceTest {
    private static final String USER_ID_1 = "user-id-1";
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

        String credentialIssuerId = "cred_issuer_id_1";
        String userId = "user-id-1";

        verifiableCredentialService.persistUserCredentials(
                SignedJWT.parse(VC_PASSPORT_NON_DCMAW_SUCCESSFUL), credentialIssuerId, userId);
        verify(mockDataStore).create(userIssuedCredentialsItemCaptor.capture());
        VcStoreItem vcStoreItem = userIssuedCredentialsItemCaptor.getValue();
        assertEquals(userId, vcStoreItem.getUserId());
        assertEquals(credentialIssuerId, vcStoreItem.getCredentialIssuer());
        assertEquals(Instant.parse("2024-01-24T02:04:14Z"), vcStoreItem.getExpirationTime());
        assertEquals(VC_PASSPORT_NON_DCMAW_SUCCESSFUL, vcStoreItem.getCredential());
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

        ArgumentCaptor<VcStoreItem> userIssuedCredentialsItemCaptor =
                ArgumentCaptor.forClass(VcStoreItem.class);

        verifiableCredentialService.persistUserCredentials(signedJwt, credentialIssuerId, userId);

        verify(mockDataStore).create(userIssuedCredentialsItemCaptor.capture());
        VcStoreItem vcStoreItem = userIssuedCredentialsItemCaptor.getValue();

        assertNull(vcStoreItem.getExpirationTime());
        assertEquals(userId, vcStoreItem.getUserId());
        assertEquals(credentialIssuerId, vcStoreItem.getCredentialIssuer());
        assertEquals(signedJwt.serialize(), vcStoreItem.getCredential());
    }

    @Test
    void expectedExceptionWhenSaveCredentials() throws Exception {
        String credentialIssuerId = "cred_issuer_id_1";
        String userId = "user-id-1";

        doThrow(new UnsupportedOperationException()).when(mockDataStore).create(any(), any());

        SignedJWT signedJwt = SignedJWT.parse(VC_PASSPORT_NON_DCMAW_SUCCESSFUL);
        VerifiableCredentialException thrown =
                assertThrows(
                        VerifiableCredentialException.class,
                        () ->
                                verifiableCredentialService.persistUserCredentials(
                                        signedJwt, credentialIssuerId, userId));

        assertNotNull(thrown);
        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_SAVE_CREDENTIAL, thrown.getErrorResponse());
    }

    @Test
    void expectedExceptionWithoutAnySignerWhenSaveCredentialsForIllegalStateException() {
        String credentialIssuerId = "cred_issuer_id_1";
        String userId = "user-id-1";

        SignedJWT signedJwt =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).build(),
                        new JWTClaimsSet.Builder().expirationTime(new Date()).build());

        VerifiableCredentialException thrown =
                assertThrows(
                        VerifiableCredentialException.class,
                        () ->
                                verifiableCredentialService.persistUserCredentials(
                                        signedJwt, credentialIssuerId, userId));

        assertNotNull(thrown);
        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_SAVE_CREDENTIAL, thrown.getErrorResponse());
        verify(mockDataStore, Mockito.times(0)).create(any(), any());
    }

    @Test
    void expectedExceptionWhenSaveCredentialsForParseException() throws Exception {
        String credentialIssuerId = "cred_issuer_id_1";
        String userId = "user-id-1";

        SignedJWT signedJwt = Mockito.mock(SignedJWT.class);

        when(signedJwt.serialize()).thenReturn("credential-serialize");
        when(signedJwt.getJWTClaimsSet()).thenThrow(java.text.ParseException.class);

        VerifiableCredentialException thrown =
                assertThrows(
                        VerifiableCredentialException.class,
                        () ->
                                verifiableCredentialService.persistUserCredentials(
                                        signedJwt, credentialIssuerId, userId));

        assertNotNull(thrown);
        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_SAVE_CREDENTIAL, thrown.getErrorResponse());
        verify(mockDataStore, Mockito.times(0)).create(any(), any());
    }

    @Test
    void expectedSuccessWhenSaveCredentialsIfNotExists() throws Exception {
        // Arrange
        ArgumentCaptor<VcStoreItem> userIssuedCredentialsItemCaptor =
                ArgumentCaptor.forClass(VcStoreItem.class);

        String credentialIssuerId = "cred_issuer_id_1";
        String userId = "user-id-1";

        // Act
        verifiableCredentialService.persistUserCredentialsIfNotExists(
                SignedJWT.parse(VC_PASSPORT_NON_DCMAW_SUCCESSFUL), credentialIssuerId, userId);

        // Assert
        verify(mockDataStore).createIfNotExists(userIssuedCredentialsItemCaptor.capture());
        VcStoreItem vcStoreItem = userIssuedCredentialsItemCaptor.getValue();
        assertEquals(userId, vcStoreItem.getUserId());
        assertEquals(credentialIssuerId, vcStoreItem.getCredentialIssuer());
        assertEquals(Instant.parse("2022-05-20T12:50:54Z"), vcStoreItem.getExpirationTime());
        assertEquals(VC_PASSPORT_NON_DCMAW_SUCCESSFUL, vcStoreItem.getCredential());
    }

    @Test
    void expectedCredentialAlreadyExistsExceptionWhenSaveCredentialsIfExists() {
        // Arrange
        String credentialIssuerId = "cred_issuer_id_1";
        String userId = "user-id-1";
        doThrow(ConditionalCheckFailedException.builder().build())
                .when(mockDataStore)
                .createIfNotExists(any());

        // Act & Assert
        assertThrows(
                CredentialAlreadyExistsException.class,
                () ->
                        verifiableCredentialService.persistUserCredentialsIfNotExists(
                                SignedJWT.parse(VC_PASSPORT_NON_DCMAW_SUCCESSFUL),
                                credentialIssuerId,
                                userId));
    }

    @Test
    void expectedExceptionWhenSaveCredentialsIfEmptyForParseException() throws Exception {
        String credentialIssuerId = "cred_issuer_id_1";
        String userId = "user-id-1";

        SignedJWT signedJwt = Mockito.mock(SignedJWT.class);

        when(signedJwt.serialize()).thenReturn("credential-serialize");
        when(signedJwt.getJWTClaimsSet()).thenThrow(java.text.ParseException.class);

        VerifiableCredentialException thrown =
                assertThrows(
                        VerifiableCredentialException.class,
                        () ->
                                verifiableCredentialService.persistUserCredentialsIfNotExists(
                                        signedJwt, credentialIssuerId, userId));

        assertNotNull(thrown);
        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_SAVE_CREDENTIAL, thrown.getErrorResponse());
        verify(mockDataStore, Mockito.times(0)).create(any(), any());
    }

    @Test
    void shouldReturnCredentialIssuersFromDataStoreForSpecificUserId() {
        String userId = "userId";
        String testCredentialIssuer = PASSPORT_CRI;
        List<VcStoreItem> credentialItem =
                List.of(
                        TestFixtures.createVcStoreItem(
                                USER_ID_1, testCredentialIssuer, VC_PASSPORT_NON_DCMAW_SUCCESSFUL));

        when(mockDataStore.getItems(userId)).thenReturn(credentialItem);

        var vcStoreItems = verifiableCredentialService.getVcStoreItems(userId);

        assertTrue(
                vcStoreItems.stream()
                        .map(VcStoreItem::getCredentialIssuer)
                        .anyMatch(testCredentialIssuer::equals));
    }

    @Test
    void shouldReturnCredentialFromDataStoreForSpecificCri() {
        String ipvSessionId = "ipvSessionId";
        String criId = "criId";
        VcStoreItem credentialItem =
                TestFixtures.createVcStoreItem(
                        USER_ID_1, PASSPORT_CRI, VC_PASSPORT_NON_DCMAW_SUCCESSFUL);

        when(mockDataStore.getItem(ipvSessionId, criId)).thenReturn(credentialItem);

        VcStoreItem retrievedCredentialItem =
                verifiableCredentialService.getVcStoreItem(ipvSessionId, criId);

        assertEquals(credentialItem, retrievedCredentialItem);
    }

    @Test
    void shouldDeleteAllExistingVCs() {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        TestFixtures.createVcStoreItem(
                                "a-users-id", PASSPORT_CRI, VC_PASSPORT_NON_DCMAW_SUCCESSFUL),
                        TestFixtures.createVcStoreItem(
                                "a-users-id", EXPERIAN_FRAUD_CRI, VC_EXPERIAN_FRAUD_SCORE_1),
                        TestFixtures.createVcStoreItem(
                                "a-users-id", "sausages", VC_EXPERIAN_KBV_SCORE_2));

        when(mockDataStore.getItems("a-users-id")).thenReturn(vcStoreItems);

        verifiableCredentialService.deleteVcStoreItems("a-users-id", true);

        verify(mockDataStore).delete("a-users-id", PASSPORT_CRI);
        verify(mockDataStore).delete("a-users-id", EXPERIAN_FRAUD_CRI);
        verify(mockDataStore).delete("a-users-id", "sausages");
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }
}
