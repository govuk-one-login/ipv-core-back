package uk.gov.di.ipv.core.initialiseipvsession.service;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.IncorrectKeyException;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.config.domain.InternalOperationsConfig;
import uk.gov.di.ipv.core.library.service.ConfigService;

import static com.nimbusds.jose.JWEAlgorithm.RSA_OAEP_256;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KmsRsaDecrypterTest {

    @Mock private KmsClient mockKmsClient;

    @Mock private ConfigService mockConfigService;

    @InjectMocks private KmsRsaDecrypter underTest;

    private final Config mockConfig = mock(Config.class);
    private final InternalOperationsConfig mockSelf = mock(InternalOperationsConfig.class);

    private void stubKmsAliases() {
        when(mockConfigService.getConfiguration()).thenReturn(mockConfig);
        when(mockConfig.getSelf()).thenReturn(mockSelf);
        when(mockSelf.getClientJarKmsEncryptionKeyAliasPrimary()).thenReturn("primaryKeyAlias");
        when(mockSelf.getClientJarKmsEncryptionKeyAliasSecondary()).thenReturn("secondaryKeyAlias");
    }

    @Test
    void decrypt_whenGivenNoEncryptedKey_shouldThrowAnException() {
        // Arrange
        JWEHeader header = new JWEHeader(RSA_OAEP_256, EncryptionMethod.A256GCM);
        Base64URL encryptedKey = null;
        Base64URL iv = new Base64URL("iv");
        Base64URL cypherText = new Base64URL("cypherText");
        Base64URL authTag = new Base64URL("authTag");
        byte[] aad = new byte[] {};

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> underTest.decrypt(header, encryptedKey, iv, cypherText, authTag, aad),
                        "Expected decrypt() to throw, but it didn't");

        // Assert
        assertThat(thrown, instanceOf(JOSEException.class));
        assertThat(thrown.getMessage(), containsString("encrypted key"));
    }

    @Test
    void decrypt_whenGivenNoIv_shouldThrowAnException() {
        // Arrange
        JWEHeader header = new JWEHeader(RSA_OAEP_256, EncryptionMethod.A256GCM);
        Base64URL encryptedKey = new Base64URL("encryptedKey");
        Base64URL iv = null;
        Base64URL cypherText = new Base64URL("cypherText");
        Base64URL authTag = new Base64URL("authTag");
        byte[] aad = new byte[] {};

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> underTest.decrypt(header, encryptedKey, iv, cypherText, authTag, aad),
                        "Expected decrypt() to throw, but it didn't");

        // Assert
        assertThat(thrown, instanceOf(JOSEException.class));
        assertThat(thrown.getMessage(), containsString("IV"));
    }

    @Test
    void decrypt_whenGivenNoAuthTag_shouldThrowAnException() {
        // Arrange
        JWEHeader header = new JWEHeader(RSA_OAEP_256, EncryptionMethod.A256GCM);
        Base64URL encryptedKey = new Base64URL("encryptedKey");
        Base64URL iv = new Base64URL("iv");
        Base64URL cypherText = new Base64URL("cypherText");
        Base64URL authTag = null;
        byte[] aad = new byte[] {};

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> underTest.decrypt(header, encryptedKey, iv, cypherText, authTag, aad),
                        "Expected decrypt() to throw, but it didn't");

        // Assert
        assertThat(thrown, instanceOf(JOSEException.class));
        assertThat(thrown.getMessage(), containsString("authentication tag"));
    }

    @Test
    void decrypt_whenPrimaryKeyWorks_shouldNotTrySecondaryKey() throws JOSEException {
        // Arrange
        stubKmsAliases();
        try (var staticMock = Mockito.mockStatic(ContentCryptoProvider.class)) {
            var expectedResult = new byte[] {};
            Mockito.when(
                            ContentCryptoProvider.decrypt(
                                    any(), any(), any(), any(), any(), any(), any()))
                    .thenReturn(expectedResult);
            JWEHeader header = new JWEHeader(RSA_OAEP_256, EncryptionMethod.A256GCM);
            Base64URL encryptedKey = new Base64URL("ZW5jcnlwdGVkS2V5");
            Base64URL iv = new Base64URL("iv");
            Base64URL cypherText = new Base64URL("cypherText");
            Base64URL authTag = new Base64URL("authTag");
            byte[] aad = new byte[] {};

            when(mockKmsClient.decrypt(
                            argThat(
                                    (DecryptRequest dr) ->
                                            dr != null && dr.keyId().contains("primary"))))
                    .thenReturn(
                            DecryptResponse.builder()
                                    .plaintext(SdkBytes.fromByteArray(new byte[] {1}))
                                    .build());

            // Act
            var result = underTest.decrypt(header, encryptedKey, iv, cypherText, authTag, aad);

            // Assert
            ArgumentCaptor<DecryptRequest> decryptRequestCaptor =
                    ArgumentCaptor.forClass(DecryptRequest.class);
            verify(mockKmsClient, times(1)).decrypt(decryptRequestCaptor.capture());
            assertThat(
                    decryptRequestCaptor.getAllValues().get(0).keyId(), containsString("primary"));
            assertThat(result, equalTo(expectedResult));
        }
    }

    @Test
    void decrypt_whenPrimaryKeyIsWrong_shouldTrySecondaryKey() throws JOSEException {
        // Arrange
        stubKmsAliases();
        try (var staticMock = Mockito.mockStatic(ContentCryptoProvider.class)) {
            var expectedResult = new byte[] {};
            Mockito.when(
                            ContentCryptoProvider.decrypt(
                                    any(), any(), any(), any(), any(), any(), any()))
                    .thenReturn(expectedResult);
            JWEHeader header = new JWEHeader(RSA_OAEP_256, EncryptionMethod.A256GCM);
            Base64URL encryptedKey = new Base64URL("ZW5jcnlwdGVkS2V5");
            Base64URL iv = new Base64URL("iv");
            Base64URL cypherText = new Base64URL("cypherText");
            Base64URL authTag = new Base64URL("authTag");
            byte[] aad = new byte[] {};

            when(mockKmsClient.decrypt(
                            argThat(
                                    (DecryptRequest dr) ->
                                            dr != null && dr.keyId().contains("primary"))))
                    .thenThrow(IncorrectKeyException.builder().message("test").build());
            when(mockKmsClient.decrypt(
                            argThat(
                                    (DecryptRequest dr) ->
                                            dr != null && dr.keyId().contains("secondary"))))
                    .thenReturn(
                            DecryptResponse.builder()
                                    .plaintext(SdkBytes.fromByteArray(new byte[] {1}))
                                    .build());

            // Act
            var result = underTest.decrypt(header, encryptedKey, iv, cypherText, authTag, aad);

            // Assert
            ArgumentCaptor<DecryptRequest> decryptRequestCaptor =
                    ArgumentCaptor.forClass(DecryptRequest.class);
            verify(mockKmsClient, times(2)).decrypt(decryptRequestCaptor.capture());
            assertThat(
                    decryptRequestCaptor.getAllValues().get(0).keyId(), containsString("primary"));
            assertThat(
                    decryptRequestCaptor.getAllValues().get(1).keyId(),
                    containsString("secondary"));
            assertThat(result, equalTo(expectedResult));
        }
    }

    @Test
    void decrypt_whenPrimaryKeyFails_shouldTrySecondaryKey() throws JOSEException {
        // Arrange
        stubKmsAliases();
        try (var staticMock = Mockito.mockStatic(ContentCryptoProvider.class)) {
            var expectedResult = new byte[] {};
            Mockito.when(
                            ContentCryptoProvider.decrypt(
                                    any(), any(), any(), any(), any(), any(), any()))
                    .thenReturn(expectedResult);
            JWEHeader header = new JWEHeader(RSA_OAEP_256, EncryptionMethod.A256GCM);
            Base64URL encryptedKey = new Base64URL("ZW5jcnlwdGVkS2V5");
            Base64URL iv = new Base64URL("iv");
            Base64URL cypherText = new Base64URL("cypherText");
            Base64URL authTag = new Base64URL("authTag");
            byte[] aad = new byte[] {};

            when(mockKmsClient.decrypt(
                            argThat(
                                    (DecryptRequest dr) ->
                                            dr != null && dr.keyId().contains("primary"))))
                    .thenThrow(new RuntimeException("test"));
            when(mockKmsClient.decrypt(
                            argThat(
                                    (DecryptRequest dr) ->
                                            dr != null && dr.keyId().contains("secondary"))))
                    .thenReturn(
                            DecryptResponse.builder()
                                    .plaintext(SdkBytes.fromByteArray(new byte[] {1}))
                                    .build());

            // Act
            var result = underTest.decrypt(header, encryptedKey, iv, cypherText, authTag, aad);

            // Assert
            ArgumentCaptor<DecryptRequest> decryptRequestCaptor =
                    ArgumentCaptor.forClass(DecryptRequest.class);
            verify(mockKmsClient, times(2)).decrypt(decryptRequestCaptor.capture());
            assertThat(
                    decryptRequestCaptor.getAllValues().get(0).keyId(), containsString("primary"));
            assertThat(
                    decryptRequestCaptor.getAllValues().get(1).keyId(),
                    containsString("secondary"));
            assertThat(result, equalTo(expectedResult));
        }
    }
}
