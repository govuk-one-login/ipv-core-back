package uk.gov.di.ipv.core.library.signing;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.SignRequest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Set;

import static software.amazon.awssdk.services.kms.model.MessageType.DIGEST;
import static software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec.ECDSA_SHA_256;

public class KmsEs256Signer implements CoreSigner {

    private final KmsClient kmsClient;
    private final JCAContext jcaContext = new JCAContext();
    private final String kmsKeyId;
    private final String kid;

    public KmsEs256Signer(KmsClient kmsClient, String kmsKeyId) {
        this.kmsKeyId = kmsKeyId;
        this.kmsClient = kmsClient;
        this.kid = DigestUtils.sha256Hex(kmsKeyId);
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

        var signRequest =
                SignRequest.builder()
                        .signingAlgorithm(ECDSA_SHA_256)
                        .keyId(kmsKeyId)
                        .message(SdkBytes.fromByteArray(signingInputHash))
                        .messageType(DIGEST)
                        .build();

        var signResponse = kmsClient.sign(signRequest);

        byte[] concatSignature =
                ECDSA.transcodeSignatureToConcat(
                        signResponse.signature().asByteArray(),
                        ECDSA.getSignatureByteArrayLength(JWSAlgorithm.ES256));

        return Base64URL.encode(concatSignature);
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(JWSAlgorithm.ES256);
    }

    @Override
    public JCAContext getJCAContext() {
        return jcaContext;
    }

    @Override
    public String getKid() {
        return kid;
    }
}
