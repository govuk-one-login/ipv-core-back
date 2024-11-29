package uk.gov.di.ipv.core.library.signing;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;

import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static software.amazon.awssdk.services.kms.model.MessageType.DIGEST;
import static software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec.ECDSA_SHA_256;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.DER_SIGNATURE;

@ExtendWith(MockitoExtension.class)
class KmsEs256SignerTest {
    private static final Base64.Decoder B64_DECODER = Base64.getDecoder();
    private static final String SIGNATURE =
            "GS0KQ+D9O4llxqaQ+BROVqvr9EPP0m3ybj/8hHxJHQY="; // pragma: allowlist secret
    private static final String KMS_KEY_ID = "kmsKeyId";
    @Mock private KmsClient kmsClient;
    @Mock private SignResponse signResponse;

    @Test
    void shouldSignJWSObject() throws Exception {
        var expectedSignRequest =
                SignRequest.builder()
                        .signingAlgorithm(ECDSA_SHA_256)
                        .keyId(KMS_KEY_ID)
                        .message(SdkBytes.fromByteArray(B64_DECODER.decode(SIGNATURE)))
                        .messageType(DIGEST)
                        .build();

        when(kmsClient.sign(expectedSignRequest)).thenReturn(signResponse);

        byte[] bytes = Base64URL.from(DER_SIGNATURE).decode();
        when(signResponse.signature()).thenReturn(SdkBytes.fromByteArray(bytes));
        KmsEs256Signer kmsSigner = new KmsEs256Signer(kmsClient, KMS_KEY_ID);

        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256).build();
        var testPayload = new Payload(Map.of("test", "test"));
        JWSObject jwsObject = new JWSObject(jwsHeader, testPayload);

        jwsObject.sign(kmsSigner);

        assertEquals(JWSObject.State.SIGNED, jwsObject.getState());
        assertEquals(jwsHeader, jwsObject.getHeader());
        assertEquals(testPayload, jwsObject.getPayload());
    }
}
