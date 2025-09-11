package uk.gov.di.ipv.core.library.helpers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.signing.LocalECDSASigner;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.DID_STORED_IDENTITY_ID;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.DER_SIGNATURE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.TEST_EC_PUBLIC_JWK;

@ExtendWith(MockitoExtension.class)
class JwtHelperTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    @Mock ConfigService mockConfigService;

    @Test
    void shouldCreateValidSignedJWT() throws Exception {
        var signer = new LocalECDSASigner(getPrivateKey());
        var exampleClaimsSet = new JWTClaimsSet.Builder().claim("exampleField", "test").build();

        var signedJWT = JwtHelper.createSignedJwt(exampleClaimsSet, signer);
        var generatedClaims = signedJWT.getJWTClaimsSet();

        assertTrue(signedJWT.verify(new ECDSAVerifier(ECKey.parse(TEST_EC_PUBLIC_JWK))));

        var claimsSet = OBJECT_MAPPER.readTree(generatedClaims.toString());
        assertEquals("test", claimsSet.get("exampleField").asText());

        assertEquals("test-fixtures-ec-key", signedJWT.getHeader().getKeyID());
    }

    @Test
    void shouldCreateValidSignedJWTForSis() throws Exception {
        when(mockConfigService.getEnvironmentVariable(DID_STORED_IDENTITY_ID))
                .thenReturn("some-id");

        var signer = new LocalECDSASigner(getPrivateKey());
        var exampleClaimsSet = new JWTClaimsSet.Builder().claim("exampleField", "test").build();

        var signedJWT = JwtHelper.createSisSignedJwt(exampleClaimsSet, signer, mockConfigService);
        var generatedClaims = signedJWT.getJWTClaimsSet();

        assertTrue(signedJWT.verify(new ECDSAVerifier(ECKey.parse(TEST_EC_PUBLIC_JWK))));

        var claimsSet = OBJECT_MAPPER.readTree(generatedClaims.toString());
        assertEquals("test", claimsSet.get("exampleField").asText());

        assertEquals("some-id#test-fixtures-ec-key", signedJWT.getHeader().getKeyID());
    }

    @Test
    void testTranscodeSignature() throws Exception {
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

        JsonNode expectedClaimsSet =
                OBJECT_MAPPER.readTree(signatureJwt.getJWTClaimsSet().toString());
        assertEquals(sub, expectedClaimsSet.get("sub").asText());
        assertEquals(aud, expectedClaimsSet.get("aud").asText());
    }

    private ECKey getPrivateKey() throws ParseException {
        return ECKey.parse(EC_PRIVATE_KEY_JWK);
    }
}
