package uk.gov.di.ipv.core.library.helpers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.SharedAttributes;
import uk.gov.di.ipv.core.library.domain.SharedAttributesResponse;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtHelperTest {

    public static final String BASE64_SIGNING_KEY =
            "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";

    @Test
    void shouldCreateValidSignedJWT()
            throws InvalidKeySpecException, NoSuchAlgorithmException, JOSEException,
                    ParseException {
        RSAPrivateKey privateKey = getSigningPrivateKey();

        String dateOfBirth = "1969-20-07";
        String familyName = "Holmes";
        List<String> givenNames = List.of("Sherlock");
        Name name = new Name(givenNames, familyName);

        SharedAttributes sharedAttributes =
                new SharedAttributes.Builder().setName(name).setDateOfBirth("1969-20-07").build();

        SharedAttributesResponse sharedAttributesResponse =
                SharedAttributesResponse.from(List.of(sharedAttributes));

        SignedJWT signedJWT =
                JwtHelper.createSignedJwtFromObject(sharedAttributesResponse, privateKey);
        JWTClaimsSet generatedClaims = signedJWT.getJWTClaimsSet();

        assertTrue(
                signedJWT.verify(
                        new RSASSAVerifier((RSAPublicKey) getSigningPublicKey(privateKey))));
        assertEquals(List.of(dateOfBirth), generatedClaims.getClaim("dateOfBirths"));
        List<Map<String, Object>> names =
                (List<Map<String, Object>>) generatedClaims.getClaim("names");
        assertEquals(name.getFamilyName(), names.get(0).get("familyName"));
        assertEquals(
                name.getGivenNames().get(0),
                ((List<String>) names.get(0).get("givenNames")).get(0));
    }

    private RSAPrivateKey getSigningPrivateKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (RSAPrivateKey)
                KeyFactory.getInstance("RSA")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(BASE64_SIGNING_KEY)));
    }

    private PublicKey getSigningPublicKey(RSAPrivateKey signingPrivateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) signingPrivateKey;
        RSAPublicKeySpec keySpec =
                new RSAPublicKeySpec(
                        rsaPrivateCrtKey.getModulus(), rsaPrivateCrtKey.getPublicExponent());
        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }
}
