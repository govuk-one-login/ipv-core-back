package uk.gov.di.ipv.core.library.service;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import javax.crypto.spec.SecretKeySpec;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.Set;

import static com.amazonaws.services.kms.model.EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256;
import static com.nimbusds.jose.JWEAlgorithm.RSA_OAEP_256;

@ExcludeFromGeneratedCoverageReport
public class KmsRsaDecrypter implements JWEDecrypter {
    private static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS = Set.of(JWEAlgorithm.RSA_OAEP_256);
    private static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS =
            Set.of(EncryptionMethod.A256GCM);

    private final AWSKMS kmsClient;
    private final String keyId;
    private final JWEJCAContext jwejcaContext = new JWEJCAContext();

    public KmsRsaDecrypter(String keyId) {
        this.keyId = keyId;
        this.kmsClient = AWSKMSClientBuilder.defaultClient();
    }

    public KmsRsaDecrypter(String keyId, AWSKMS kmsClient) {
        this.keyId = keyId;
        this.kmsClient = kmsClient;
    }

    @Override
    public byte[] decrypt(
            JWEHeader header,
            Base64URL encryptedKey,
            Base64URL iv,
            Base64URL cipherText,
            Base64URL authTag)
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

        DecryptRequest encryptedKeyDecryptRequest =
                new DecryptRequest()
                        .withCiphertextBlob(ByteBuffer.wrap(encryptedKey.decode()))
                        .withEncryptionAlgorithm(RSAES_OAEP_SHA_256)
                        .withKeyId(keyId);

        DecryptResult decryptResult = kmsClient.decrypt(encryptedKeyDecryptRequest);

        SecretKeySpec contentEncryptionKey =
                new SecretKeySpec(decryptResult.getPlaintext().array(), "AES");

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
