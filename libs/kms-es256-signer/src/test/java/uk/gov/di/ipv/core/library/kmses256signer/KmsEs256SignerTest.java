package uk.gov.di.ipv.core.library.kmses256signer;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.MessageType;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.amazonaws.services.kms.model.SigningAlgorithmSpec;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.DER_SIGNATURE;

@ExtendWith(MockitoExtension.class)
class KmsEs256SignerTest {
    private static final Base64.Decoder B64_DECODER = Base64.getDecoder();
    @Mock private AWSKMS kmsClient;
    @Mock private SignResult signResult;

    @Test
    void shouldSignJWSObject() throws JOSEException {
        SignRequest expectedSignRequest =
                new SignRequest()
                        .withSigningAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256.toString())
                        .withKeyId("kmsKeyId")
                        .withMessage(
                                ByteBuffer.wrap(
                                        B64_DECODER.decode(
                                                "GS0KQ+D9O4llxqaQ+BROVqvr9EPP0m3ybj/8hHxJHQY=")))
                        .withMessageType(MessageType.DIGEST);

        when(kmsClient.sign(expectedSignRequest)).thenReturn(signResult);

        byte[] bytes = Base64URL.from(DER_SIGNATURE).decode();
        when(signResult.getSignature()).thenReturn(ByteBuffer.wrap(bytes));
        KmsEs256Signer kmsSigner = new KmsEs256Signer(kmsClient, "kmsKeyId");

        JSONObject jsonPayload = new JSONObject(Map.of("test", "test"));

        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256).build();
        JWSObject jwsObject = new JWSObject(jwsHeader, new Payload(jsonPayload));

        jwsObject.sign(kmsSigner);

        assertEquals(JWSObject.State.SIGNED, jwsObject.getState());
        assertEquals(jwsHeader, jwsObject.getHeader());
        assertEquals(jsonPayload.toJSONString(), jwsObject.getPayload().toString());
    }
}
