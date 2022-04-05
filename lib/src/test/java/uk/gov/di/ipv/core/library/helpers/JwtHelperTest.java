package uk.gov.di.ipv.core.library.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.NameParts;
import uk.gov.di.ipv.core.library.domain.SharedAttributes;
import uk.gov.di.ipv.core.library.domain.SharedAttributesResponse;

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

        String generatedClaimsValue = "";
        String generatedClaimsType = "";
        String generatedClaimsValidFrom = "";
        String generatedClaimsValidUntil = "";
        String generatedClaimsbirthDate = "";

        Set<Name> nameSet = new HashSet<>();
        nameSet.add(
                new Name(List.of(new NameParts("Paul", "GivenName", "2020-03-03", "2021-04-04"))));

        Set<BirthDate> birthDaySet = new HashSet<>();
        birthDaySet.add(new BirthDate("2020-02-03"));

        SharedAttributes sharedAttributes =
                new SharedAttributes.Builder().setName(nameSet).setBirthDate(birthDaySet).build();

        SharedAttributesResponse sharedAttributesResponse =
                SharedAttributesResponse.from(List.of(sharedAttributes));

        SignedJWT signedJWT = JwtHelper.createSignedJwtFromObject(sharedAttributesResponse, signer);
        JWTClaimsSet generatedClaims = signedJWT.getJWTClaimsSet();

        assertTrue(signedJWT.verify(new ECDSAVerifier(ECKey.parse(EC_PUBLIC_JWK))));

        JsonNode claimsSet = objectMapper.readTree(generatedClaims.toString());

        JsonNode nameNode = claimsSet.get("name");
        if (nameNode != null) {
            for (JsonNode jo : nameNode) {
                generatedClaimsValue = jo.get("nameParts").get(0).get("value").asText();
                generatedClaimsType = jo.get("nameParts").get(0).get("type").asText();
                generatedClaimsValidFrom = jo.get("nameParts").get(0).get("validFrom").asText();
                generatedClaimsValidUntil = jo.get("nameParts").get(0).get("validUntil").asText();
            }
        }
        JsonNode bdateNode = claimsSet.get("birthDate");
        if (bdateNode != null) {
            for (JsonNode jo : bdateNode) {
                generatedClaimsbirthDate = jo.get("value").asText();
            }
        }

        assertEquals("Paul", generatedClaimsValue);
        assertEquals("GivenName", generatedClaimsType);
        assertEquals("2020-03-03", generatedClaimsValidFrom);
        assertEquals("2021-04-04", generatedClaimsValidUntil);
        assertEquals("2020-02-03", generatedClaimsbirthDate);
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }
}
