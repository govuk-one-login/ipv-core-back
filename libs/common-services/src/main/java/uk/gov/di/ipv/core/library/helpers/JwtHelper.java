package uk.gov.di.ipv.core.library.helpers;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.text.ParseException;
import java.util.Map;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.SIGNING_KEY_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.SIGNING_KEY_JWK;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.KID_JAR_HEADER;

public class JwtHelper {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Logger LOGGER = LogManager.getLogger();

    private JwtHelper() {}

    public static <T> SignedJWT createSignedJwtFromObject(
            T claimInput, JWSSigner signer, ConfigService configService) throws JOSEException {
        JWSHeader jwsHeader = generateHeader(configService);
        JWTClaimsSet claimsSet = generateClaims(claimInput);
        SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
        signedJWT.sign(signer);
        return signedJWT;
    }

    public static JWSHeader generateHeader(ConfigService configService) {
        return new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType.JWT)
                .keyID(configService.enabled(KID_JAR_HEADER) ? getKid(configService) : null)
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

    private static String getKid(ConfigService configService) {
        if (ConfigService.isLocal()) {
            try {
                return ECKey.parse(configService.getSecret(SIGNING_KEY_JWK)).getKeyID();
            } catch (ParseException e) {
                LOGGER.warn(LogHelper.buildLogMessage("Missing signing key JWK"));
                return null;
            }
        }
        return DigestUtils.sha256Hex(configService.getParameter(SIGNING_KEY_ID));
    }

    private static <T> JWTClaimsSet generateClaims(T claimInput) {
        var claimsBuilder = new JWTClaimsSet.Builder();

        OBJECT_MAPPER
                .convertValue(claimInput, new TypeReference<Map<String, Object>>() {})
                .forEach(claimsBuilder::claim);

        return claimsBuilder.build();
    }
}
