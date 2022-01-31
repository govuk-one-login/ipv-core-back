package uk.gov.di.ipv.core.library.helpers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.util.Map;

public class JwtHelper {

    private static final ObjectMapper mapper = new ObjectMapper();

    public static <T> SignedJWT createSignedJwtFromObject(T claimInput, JWSSigner signer)
            throws JOSEException {
        JWSHeader jwsHeader = generateHeader();
        JWTClaimsSet claimsSet = generateClaims(claimInput);
        SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
        signedJWT.sign(signer);
        return signedJWT;
    }

    private static <T> JWSHeader generateHeader() {
        return new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();
    }

    private static <T> JWTClaimsSet generateClaims(T claimInput) {
        var claimsBuilder = new JWTClaimsSet.Builder();

        mapper.convertValue(claimInput, Map.class)
                .forEach((key, value) -> claimsBuilder.claim((String) key, value));

        return claimsBuilder.build();
    }
}
