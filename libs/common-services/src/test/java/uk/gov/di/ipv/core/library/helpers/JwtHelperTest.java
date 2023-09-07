package uk.gov.di.ipv.core.library.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
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
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
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

        if (JwtHelper.signatureIsDerFormat(signedJWT)) {
            String[] jwtParts = signedJWT.serialize().split("\\.");
            Base64URL derSignature =
                    Base64URL.encode(
                            ECDSA.transcodeSignatureToConcat(
                                    signedJWT.getSignature().decode(),
                                    ECDSA.getSignatureByteArrayLength(JWSAlgorithm.ES256)));
            SignedJWT derSignatureJwt =
                    SignedJWT.parse(
                            String.format("%s.%s.%s", jwtParts[0], jwtParts[1], derSignature));
            assertEquals(derSignatureJwt, JwtHelper.transcodeSignature(signedJWT));
        }
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }
}
