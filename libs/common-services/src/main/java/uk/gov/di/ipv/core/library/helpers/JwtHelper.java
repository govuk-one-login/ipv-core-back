package uk.gov.di.ipv.core.library.helpers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.signing.CoreSigner;

import java.text.ParseException;
import java.util.Base64;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.DID_STORED_IDENTITY_ID;

public class JwtHelper {
    private JwtHelper() {}

    public static SignedJWT createSisSignedJwt(
            JWTClaimsSet claimsSet, CoreSigner signer, ConfigService configService)
            throws JOSEException {
        var constructedKid =
                configService.getEnvironmentVariable(DID_STORED_IDENTITY_ID)
                        + "#"
                        + signer.getKid();
        JWSHeader jwsHeader = generateHeader(constructedKid);
        SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
        signedJWT.sign(signer);
        return signedJWT;
    }

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
            throws JOSEException, ParseException {
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

    // Only enforces strict Base64URL encoding when enforceBase64Url is true, gated behind
    // CoreFeatureFlag.ENFORCE_BASE64URL_VC_ENCODING at call sites. See validateBase64UrlEncoding
    // for the encoding rule being enforced.
    public static SignedJWT parseBase64URLJWT(String token, boolean enforceBase64Url)
            throws ParseException {
        if (enforceBase64Url) {
            validateBase64UrlEncoding(token);
        }
        return SignedJWT.parse(token);
    }

    // EVCS will not parse VC JWT strings that are Base64, rather than Base64URL, encoded.
    // The JWT specification (https://datatracker.ietf.org/doc/html/rfc7515) states that
    // Base64URL encoded strings must use its URL- and filename-safe character set,
    // with all trailing '=' characters omitted.
    private static void validateBase64UrlEncoding(String token) throws ParseException {
        String[] jwtParts = token.split("\\.");
        try {
            for (String jwtPart : jwtParts) {
                if (isPadded(jwtPart)) {
                    throw new ParseException("JWT is not valid Base64URL: contains padding", 0);
                }
                Base64.getUrlDecoder().decode(jwtPart);
            }
        } catch (IllegalArgumentException e) {
            throw new ParseException("JWT is not valid Base64URL: invalid characters", 0);
        }
    }

    private static boolean isPadded(String jwtPart) {
        return jwtPart.endsWith("=");
    }
}
