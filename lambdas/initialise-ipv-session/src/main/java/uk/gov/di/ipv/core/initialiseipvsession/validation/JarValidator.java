package uk.gov.di.ipv.core.initialiseipvsession.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.services.ssm.model.ParameterNotFoundException;
import uk.gov.di.ipv.core.initialiseipvsession.domain.JarClaims;
import uk.gov.di.ipv.core.initialiseipvsession.exception.JarValidationException;
import uk.gov.di.ipv.core.initialiseipvsession.exception.RecoverableJarValidationException;
import uk.gov.di.ipv.core.initialiseipvsession.service.KmsRsaDecrypter;
import uk.gov.di.ipv.core.library.helpers.JwtHelper;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.net.URI;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CLIENT_ISSUER;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.MAX_ALLOWED_AUTH_CLIENT_TTL;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CLIENT_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_JWT_ALGORITHM;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_REDIRECT_URI;

public class JarValidator {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String REDIRECT_URI_CLAIM = "redirect_uri";
    public static final String CLAIMS_CLAIM = "claims";

    private final KmsRsaDecrypter kmsRsaDecrypter;
    private final ConfigService configService;

    public JarValidator(KmsRsaDecrypter kmsRsaDecrypter, ConfigService configService) {
        this.kmsRsaDecrypter = kmsRsaDecrypter;
        this.configService = configService;
    }

    public SignedJWT decryptJWE(JWEObject jweObject, String keyId) throws JarValidationException {
        try {
            kmsRsaDecrypter.setKeyId(keyId);
            jweObject.decrypt(kmsRsaDecrypter);

            return jweObject.getPayload().toSignedJWT();
        } catch (JOSEException e) {
            LOGGER.error(LogHelper.buildLogMessage("Failed to decrypt the JWE"));
            throw new JarValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            "Failed to decrypt the contents of the JAR"));
        }
    }

    public JWTClaimsSet validateRequestJwt(SignedJWT signedJWT, String clientId)
            throws JarValidationException, ParseException {
        validateClientId(clientId);
        validateJWTHeader(signedJWT);
        validateSignature(signedJWT, clientId);

        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
        URI redirectUri = validateRedirectUri(jwtClaimsSet, clientId);

        try {
            return getValidatedClaimSet(signedJWT, clientId);
        } catch (JarValidationException e) {
            throw new RecoverableJarValidationException(
                    e.getErrorObject(),
                    redirectUri.toString(),
                    clientId,
                    jwtClaimsSet.getStringClaim("state"),
                    jwtClaimsSet.getStringClaim("govuk_signin_journey_id"));
        }
    }

    private void validateClientId(String clientId) throws JarValidationException {
        try {
            configService.getSsmParameter(CLIENT_ISSUER, clientId);
            LogHelper.attachClientIdToLogs(clientId);
        } catch (ParameterNotFoundException e) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Unknown client id provided.")
                            .with(LOG_CLIENT_ID.getFieldName(), clientId));
            throw new JarValidationException(
                    OAuth2Error.INVALID_CLIENT.setDescription("Unknown client id was provided"));
        }
    }

    private void validateJWTHeader(SignedJWT signedJWT) throws JarValidationException {
        JWSAlgorithm jwtAlgorithm = signedJWT.getHeader().getAlgorithm();
        if (jwtAlgorithm != JWSAlgorithm.ES256) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "jwt signing algorithm does not match expected signing algorithm ES256.")
                            .with(LOG_JWT_ALGORITHM.getFieldName(), jwtAlgorithm));
            throw new JarValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            "Signing algorithm used does not match required algorithm"));
        }
    }

    private void validateSignature(SignedJWT signedJWT, String clientId)
            throws JarValidationException {
        try {
            SignedJWT concatSignatureJwt;
            if (JwtHelper.signatureIsDerFormat(signedJWT)) {
                concatSignatureJwt = JwtHelper.transcodeSignature(signedJWT);
            } else {
                concatSignatureJwt = signedJWT;
            }
            boolean valid =
                    concatSignatureJwt.verify(
                            new ECDSAVerifier(
                                    ECKey.parse(
                                                    configService.getSsmParameter(
                                                            PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY,
                                                            clientId))
                                            .toECPublicKey()));

            if (!valid) {
                LOGGER.error(LogHelper.buildLogMessage("JWT signature validation failed"));
                throw new JarValidationException(
                        OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                                "JWT signature validation failed"));
            }
        } catch (JOSEException | ParseException e) {
            LOGGER.error(
                    LogHelper.buildLogMessage(
                            "Failed to parse JWT when attempting signature validation"));
            throw new JarValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            "Failed to parse JWT when attempting signature validation"));
        }
    }

    private JWTClaimsSet getValidatedClaimSet(SignedJWT signedJWT, String clientId)
            throws JarValidationException {

        String criAudience = configService.getSsmParameter(COMPONENT_ID);
        String clientIssuer = configService.getSsmParameter(CLIENT_ISSUER, clientId);

        DefaultJWTClaimsVerifier<?> verifier =
                new DefaultJWTClaimsVerifier<>(
                        criAudience,
                        new JWTClaimsSet.Builder()
                                .claim("client_id", clientId)
                                .issuer(clientIssuer)
                                .claim("response_type", "code")
                                .build(),
                        Set.of(
                                JWTClaimNames.EXPIRATION_TIME,
                                JWTClaimNames.NOT_BEFORE,
                                JWTClaimNames.ISSUED_AT,
                                JWTClaimNames.SUBJECT));

        try {
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            verifier.verify(claimsSet, null);

            validateMaxAllowedJarTtl(claimsSet);
            validateInheritedIdentityJwtClaim(claimsSet);

            return claimsSet;
        } catch (BadJWTException | ParseException e) {
            LOGGER.error(LogHelper.buildLogMessage("Claim set validation failed"));
            throw new JarValidationException(
                    OAuth2Error.INVALID_GRANT.setDescription(e.getMessage()));
        }
    }

    private void validateMaxAllowedJarTtl(JWTClaimsSet claimsSet) throws JarValidationException {
        String maxAllowedTtl = configService.getSsmParameter(MAX_ALLOWED_AUTH_CLIENT_TTL);
        LocalDateTime maximumExpirationTime =
                LocalDateTime.now().plusSeconds(Long.parseLong(maxAllowedTtl));
        LocalDateTime expirationTime =
                LocalDateTime.ofInstant(claimsSet.getExpirationTime().toInstant(), ZoneOffset.UTC);

        if (expirationTime.isAfter(maximumExpirationTime)) {
            LOGGER.error(
                    LogHelper.buildLogMessage("Client JWT expiry date is too far in the future"));
            throw new JarValidationException(
                    OAuth2Error.INVALID_GRANT.setDescription(
                            "The client JWT expiry date has surpassed the maximum allowed ttl value"));
        }
    }

    private URI validateRedirectUri(JWTClaimsSet claimsSet, String clientId)
            throws JarValidationException {
        try {
            URI redirectUri = claimsSet.getURIClaim(REDIRECT_URI_CLAIM);
            List<String> allowedRedirectUris = configService.getClientRedirectUrls(clientId);

            if (redirectUri == null || !allowedRedirectUris.contains(redirectUri.toString())) {
                LOGGER.error(
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "Invalid redirect_uri claim provided for client.")
                                .with(LOG_CLIENT_ID.getFieldName(), clientId)
                                .with(LOG_REDIRECT_URI.getFieldName(), redirectUri));
                throw new JarValidationException(
                        OAuth2Error.INVALID_GRANT.setDescription(
                                "Invalid redirct_uri claim provided for configured client"));
            }
            return redirectUri;
        } catch (ParseException e) {
            LOGGER.error(
                    LogHelper.buildLogMessage(
                            "Failed to parse JWT claim set in order to access to the redirect_uri claim"));
            throw new JarValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            "Failed to parse JWT claim set in order to access redirect_uri claim"));
        }
    }

    private void validateInheritedIdentityJwtClaim(JWTClaimsSet claimsSet)
            throws JarValidationException {
        var claims = (JarClaims) claimsSet.getClaim(CLAIMS_CLAIM);
        if (claims == null) {
            return;
        }

        var userInfo = claims.userInfo();
        if (userInfo == null) {
            return;
        }

        var inheritedIdentityJwtClaim = userInfo.inheritedIdentityClaim();
        if (inheritedIdentityJwtClaim == null) {
            return;
        }

        List<String> inheritedIdentityJwtList = inheritedIdentityJwtClaim.value();
        if (inheritedIdentityJwtList == null) {
            throw new JarValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            "Inherited identity jwt claim received but value is null"));
        }
        if (inheritedIdentityJwtList.size() != 1) {
            throw new JarValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            String.format(
                                    "%d inherited identity jwts received - one expected",
                                    inheritedIdentityJwtList.size())));
        }
    }
}
