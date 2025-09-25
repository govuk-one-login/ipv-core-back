package uk.gov.di.ipv.core.initialiseipvsession.service;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.IncorrectKeyException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.service.ConfigService;

import javax.crypto.spec.SecretKeySpec;

import java.util.Objects;
import java.util.Set;

import static com.nimbusds.jose.JWEAlgorithm.RSA_OAEP_256;
import static software.amazon.awssdk.regions.Region.EU_WEST_2;
import static software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256;

public class KmsRsaDecrypter implements JWEDecrypter {
    private static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS = Set.of(JWEAlgorithm.RSA_OAEP_256);
    private static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS =
            Set.of(EncryptionMethod.A256GCM);
    private static final Logger LOGGER = LogManager.getLogger();

    private final ConfigService configService;
    private final KmsClient kmsClient;
    private final JWEJCAContext jwejcaContext = new JWEJCAContext();

    @ExcludeFromGeneratedCoverageReport
    public KmsRsaDecrypter(ConfigService configService) {
        this.configService = configService;
        this.kmsClient =
                KmsClient.builder()
                        .region(EU_WEST_2)
                        .httpClientBuilder(UrlConnectionHttpClient.builder())
                        .build();
    }

    public KmsRsaDecrypter(ConfigService configService, KmsClient kmsClient) {
        this.configService = configService;
        this.kmsClient = kmsClient;
    }

    @Override
    public byte[] decrypt(
            JWEHeader header,
            Base64URL encryptedKey,
            Base64URL iv,
            Base64URL cipherText,
            Base64URL authTag,
            byte[] aad)
            throws JOSEException {
        if (Objects.isNull(encryptedKey)) {
            throw new JOSEException("Missing JWE encrypted key");
        }

        if (Objects.isNull(iv)) {
            throw new JOSEException("Missing JWE initialization vector (IV)");
        }

        if (Objects.isNull(authTag)) {
            throw new JOSEException("Missing JWE authentication tag");
        }

        JWEAlgorithm alg = header.getAlgorithm();

        if (!SUPPORTED_ALGORITHMS.contains(alg)) {
            throw new JOSEException(
                    AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, supportedJWEAlgorithms()));
        }

        var primaryKeyAlias =
                configService
                        .getConfiguration()
                        .getSelf()
                        .getClientJarKmsEncryptionKeyAliasPrimary();
        var secondaryKeyAlias =
                configService
                        .getConfiguration()
                        .getSelf()
                        .getClientJarKmsEncryptionKeyAliasSecondary();

        var encryptedKeyDecryptRequestPrimary =
                DecryptRequest.builder()
                        .ciphertextBlob(SdkBytes.fromByteArray(encryptedKey.decode()))
                        .encryptionAlgorithm(RSAES_OAEP_SHA_256)
                        .keyId("alias/" + primaryKeyAlias)
                        .build();

        var encryptedKeyDecryptRequestSecondary =
                DecryptRequest.builder()
                        .ciphertextBlob(SdkBytes.fromByteArray(encryptedKey.decode()))
                        .encryptionAlgorithm(RSAES_OAEP_SHA_256)
                        .keyId("alias/" + secondaryKeyAlias)
                        .build();

        // During a key rotation we might receive JWTs encrypted with either the old or new key.
        DecryptResponse decryptResponse;
        try {
            decryptResponse = kmsClient.decrypt(encryptedKeyDecryptRequestPrimary);
        } catch (IncorrectKeyException e) {
            decryptResponse = kmsClient.decrypt(encryptedKeyDecryptRequestSecondary);
        } catch (Exception e) {
            // We only expect to get IncorrectKeyExceptions, but if we get another error we should
            // still try the secondary key
            LOGGER.warn(
                    "Unexpected exception decrypting JWT key with primary key. Trying secondary key. %s"
                            .formatted(e.getMessage()));
            decryptResponse = kmsClient.decrypt(encryptedKeyDecryptRequestSecondary);
        }

        SecretKeySpec contentEncryptionKey =
                new SecretKeySpec(decryptResponse.plaintext().asByteArray(), "AES");

        return ContentCryptoProvider.decrypt(
                header, encryptedKey, iv, cipherText, authTag, contentEncryptionKey, jwejcaContext);
    }

    @Override
    public Set<JWEAlgorithm> supportedJWEAlgorithms() {
        return Set.of(RSA_OAEP_256);
    }

    @Override
    public Set<EncryptionMethod> supportedEncryptionMethods() {
        return SUPPORTED_ENCRYPTION_METHODS;
    }

    @Override
    public JWEJCAContext getJCAContext() {
        return jwejcaContext;
    }
}
