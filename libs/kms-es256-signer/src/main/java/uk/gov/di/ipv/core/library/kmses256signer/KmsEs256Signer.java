package uk.gov.di.ipv.core.library.kmses256signer;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.MessageType;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.amazonaws.services.kms.model.SigningAlgorithmSpec;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Set;

public class KmsEs256Signer implements JWSSigner {

    private final AWSKMS kmsClient;

    private static final Base64.Encoder b64UrlEncoder = Base64.getUrlEncoder();
    private final JCAContext jcaContext = new JCAContext();
    private String keyId;

    @ExcludeFromGeneratedCoverageReport
    public KmsEs256Signer() {
        this.kmsClient = AWSKMSClientBuilder.defaultClient();
    }

    public KmsEs256Signer(AWSKMS kmsClient) {
        this.kmsClient = kmsClient;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        byte[] signingInputHash;

        try {
            signingInputHash =
                    MessageDigest.getInstance(MessageDigestAlgorithms.SHA_256).digest(signingInput);
        } catch (NoSuchAlgorithmException e) {
            throw new JOSEException(e.getMessage());
        }

        SignRequest signRequest =
                new SignRequest()
                        .withSigningAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256.toString())
                        .withKeyId(keyId)
                        .withMessage(ByteBuffer.wrap(signingInputHash))
                        .withMessageType(MessageType.DIGEST);

        SignResult signResult = kmsClient.sign(signRequest);

        byte[] concatSignature =
                ECDSA.transcodeSignatureToConcat(
                        signResult.getSignature().array(),
                        ECDSA.getSignatureByteArrayLength(JWSAlgorithm.ES256));

        return new Base64URL(b64UrlEncoder.encodeToString(concatSignature));
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(JWSAlgorithm.ES256);
    }

    @Override
    public JCAContext getJCAContext() {
        return jcaContext;
    }
}
