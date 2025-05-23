package uk.gov.di.ipv.core.library.helpers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import uk.gov.di.ipv.core.library.signing.CoreSigner;

public class JwtHelper {
    private JwtHelper() {}

    public static SignedJWT createSignedJwt(JWTClaimsSet claimsSet, CoreSigner signer)
            throws JOSEException {
        JWSHeader jwsHeader = generateHeader(signer.getKid());
        SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
        signedJWT.sign(signer);
        return signedJWT;
    }

    private static JWSHeader generateHeader(String kid) {
        return new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType.JWT)
                .keyID(kid)
                .build();
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
