package uk.gov.di.ipv.core.library.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.Data;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.SIGNING_KEY_ID;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.KID_JAR_HEADER;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.DER_SIGNATURE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.TEST_EC_PUBLIC_JWK;

@ExtendWith(MockitoExtension.class)
class JwtHelperTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Mock ConfigService mockConfigService;

    @Data
    private static final class ExamplePayload {
        private String exampleField;
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldCreateValidSignedJWT(boolean includeKid) throws Exception {
        var signer = new ECDSASigner(getPrivateKey());

        var exampleFieldValue = "test";
        var examplePayload = new ExamplePayload();
        examplePayload.setExampleField(exampleFieldValue);

        when(mockConfigService.enabled(KID_JAR_HEADER)).thenReturn(includeKid);
        if (includeKid) {
            when(mockConfigService.getParameter(SIGNING_KEY_ID)).thenReturn("kmsKeyId");
        }
        var signedJWT =
                JwtHelper.createSignedJwtFromObject(examplePayload, signer, mockConfigService);
        var generatedClaims = signedJWT.getJWTClaimsSet();

        assertTrue(signedJWT.verify(new ECDSAVerifier(ECKey.parse(TEST_EC_PUBLIC_JWK))));

        var claimsSet = OBJECT_MAPPER.readTree(generatedClaims.toString());
        assertEquals(exampleFieldValue, claimsSet.get("exampleField").asText());

        if (includeKid) {
            assertEquals(DigestUtils.sha256Hex("kmsKeyId"), signedJWT.getHeader().getKeyID());
        } else {
            assertNull(signedJWT.getHeader().getKeyID());
        }
    }

    @Test
    void testTranscodeSignature()
            throws InvalidKeySpecException, NoSuchAlgorithmException, JOSEException, ParseException,
                    JsonProcessingException {
        String sub = "test-user-id";
        String aud = "test-audience";
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .expirationTime(new Date(Instant.now().plusSeconds(1000).getEpochSecond()))
                        .issueTime(new Date())
                        .notBeforeTime(new Date())
                        .subject(sub)
                        .audience(aud)
                        .issuer("test-issuer")
                        .claim("response_type", "code")
                        .claim("redirect_uri", "http://example.com")
                        .claim("state", "test-state")
                        .claim("client_id", "test-client")
                        .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claimsSet);
        signedJWT.sign(new ECDSASigner(getPrivateKey()));

        var jwtParts = SignedJWT.parse(signedJWT.serialize()).getParsedParts();
        var vcWithDerSignature =
                new SignedJWT(
                        jwtParts[0],
                        jwtParts[1],
                        Base64URL.encode(
                                ECDSA.transcodeSignatureToDER(
                                        Base64URL.from(DER_SIGNATURE).decode())));

        SignedJWT signatureJwt = JwtHelper.transcodeSignature(vcWithDerSignature);
        //
        JsonNode expectedClaimsSet =
                OBJECT_MAPPER.readTree(signatureJwt.getJWTClaimsSet().toString());
        assertEquals(sub, expectedClaimsSet.get("sub").asText());
        assertEquals(aud, expectedClaimsSet.get("aud").asText());
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }
}
