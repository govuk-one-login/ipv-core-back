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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.NameParts;
import uk.gov.di.ipv.core.library.domain.SharedClaims;
import uk.gov.di.ipv.core.library.domain.SharedClaimsResponse;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.DER_SIGNATURE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK;

@ExtendWith(MockitoExtension.class)
class JwtHelperTest {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void shouldCreateValidSignedJWT()
            throws JOSEException, ParseException, InvalidKeySpecException, NoSuchAlgorithmException,
                    JsonProcessingException {
        ECDSASigner signer = new ECDSASigner(getPrivateKey());

        Set<Name> nameSet = new HashSet<>();
        nameSet.add(new Name(List.of(new NameParts("Paul", "GivenName"))));

        Set<BirthDate> birthDaySet = new HashSet<>();
        birthDaySet.add(new BirthDate("2020-02-03"));

        SharedClaims sharedClaims =
                new SharedClaims.Builder().setName(nameSet).setBirthDate(birthDaySet).build();

        SharedClaimsResponse sharedClaimsResponse =
                SharedClaimsResponse.from(Set.of(sharedClaims), null);

        SignedJWT signedJWT = JwtHelper.createSignedJwtFromObject(sharedClaimsResponse, signer);
        JWTClaimsSet generatedClaims = signedJWT.getJWTClaimsSet();

        assertTrue(signedJWT.verify(new ECDSAVerifier(ECKey.parse(EC_PUBLIC_JWK))));

        JsonNode claimsSet = objectMapper.readTree(generatedClaims.toString());
        JsonNode namePartsNode = claimsSet.get("name").get(0).get("nameParts").get(0);
        assertEquals("Paul", namePartsNode.get("value").asText());
        assertEquals("GivenName", namePartsNode.get("type").asText());
        assertEquals("2020-02-03", claimsSet.get("birthDate").get(0).get("value").asText());
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
                objectMapper.readTree(signatureJwt.getJWTClaimsSet().toString());
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
