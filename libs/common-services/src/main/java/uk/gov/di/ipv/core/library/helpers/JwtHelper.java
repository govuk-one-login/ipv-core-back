package uk.gov.di.ipv.core.library.helpers;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.digest.DigestUtils;

import java.util.Map;

public class JwtHelper {

    private static final ObjectMapper mapper = new ObjectMapper();

    private JwtHelper() {}

    public static <T> SignedJWT createSignedJwtFromObject(
            T claimInput, JWSSigner signer, boolean isKidJarHeaderEnabled, String signingKeyId)
            throws JOSEException {
        JWSHeader jwsHeader = generateHeader(isKidJarHeaderEnabled, signingKeyId);
        JWTClaimsSet claimsSet = generateClaims(claimInput);
        SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
        signedJWT.sign(signer);
        return signedJWT;
    }

    private static JWSHeader generateHeader(boolean isKidJarHeaderEnabled, String signingKeyId) {
        JWSHeader.Builder headerBuilder =
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT);
        if (isKidJarHeaderEnabled) {
            String signingKid = DigestUtils.sha256Hex(signingKeyId);
            headerBuilder.keyID(signingKid);
        }
        return headerBuilder.build();
    }

    private static <T> JWTClaimsSet generateClaims(T claimInput) {
        var claimsBuilder = new JWTClaimsSet.Builder();

        mapper.convertValue(claimInput, new TypeReference<Map<String, Object>>() {})
                .forEach(claimsBuilder::claim);

        return claimsBuilder.build();
    }

    public static SignedJWT transcodeSignature(SignedJWT signedJWT)
            throws JOSEException, java.text.ParseException {
        Base64URL transcodedSignatureBase64 =
                Base64URL.encode(
                        ECDSA.transcodeSignatureToConcat(
                                signedJWT.getSignature().decode(),
                                ECDSA.getSignatureByteArrayLength(JWSAlgorithm.ES256)));
        String[] jwtParts = signedJWT.serialize().split("\\.");
        return SignedJWT.parse(
                String.format("%s.%s.%s", jwtParts[0], jwtParts[1], transcodedSignatureBase64));
    }

    public static boolean signatureIsDerFormat(SignedJWT signedJWT) throws JOSEException {
        return signedJWT.getSignature().decode().length
                != ECDSA.getSignatureByteArrayLength(JWSAlgorithm.ES256);
    }
}
