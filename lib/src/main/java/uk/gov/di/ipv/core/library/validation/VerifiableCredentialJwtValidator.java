package uk.gov.di.ipv.core.library.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.domain.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;

import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;

import static com.nimbusds.jose.JWSAlgorithm.ES256;

public class VerifiableCredentialJwtValidator {
    private static final Logger LOGGER =
            LoggerFactory.getLogger(VerifiableCredentialJwtValidator.class);
    public static final String VC_CLAIM_NAME = "vc";

    public void validate(
            SignedJWT verifiableCredential,
            CredentialIssuerConfig credentialIssuerConfig,
            String userId)
            throws CredentialIssuerException {
        validateSignature(verifiableCredential, credentialIssuerConfig);
        validateClaimsSet(verifiableCredential, credentialIssuerConfig, userId);
    }

    private void validateSignature(
            SignedJWT verifiableCredential, CredentialIssuerConfig credentialIssuerConfig) {

        SignedJWT concatSignatureVerifiableCredential;
        try {
            concatSignatureVerifiableCredential =
                    signatureIsDerFormat(verifiableCredential)
                            ? transcodeSignature(verifiableCredential)
                            : verifiableCredential;
        } catch (JOSEException | ParseException e) {
            LOGGER.error("Error transcoding signature: '{}'", e.getMessage());
            throw new CredentialIssuerException(
                    HTTPResponse.SC_SERVER_ERROR,
                    new ErrorObject(
                            OAuth2Error.SERVER_ERROR_CODE,
                            ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL.getMessage()));
        }

        try {
            ECDSAVerifier verifier =
                    new ECDSAVerifier(credentialIssuerConfig.getVcVerifyingPublicJwk());
            if (!concatSignatureVerifiableCredential.verify(verifier)) {
                LOGGER.error("Verifiable credential signature not valid");
                throw new CredentialIssuerException(
                        HTTPResponse.SC_SERVER_ERROR,
                        new ErrorObject(
                                OAuth2Error.SERVER_ERROR_CODE,
                                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL
                                        .getMessage()));
            }
        } catch (JOSEException e) {
            LOGGER.error("JOSE exception when verifying signature: '{}'", e.getMessage());
            throw new CredentialIssuerException(
                    HTTPResponse.SC_SERVER_ERROR,
                    new ErrorObject(
                            OAuth2Error.SERVER_ERROR_CODE,
                            ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL.getMessage()));
        } catch (ParseException e) {
            LOGGER.error("Error parsing credential issuer public JWK: '{}'", e.getMessage());
            throw new CredentialIssuerException(
                    HTTPResponse.SC_SERVER_ERROR,
                    new ErrorObject(
                            OAuth2Error.SERVER_ERROR_CODE,
                            ErrorResponse.FAILED_TO_PARSE_JWK.getMessage()));
        }
    }

    private SignedJWT transcodeSignature(SignedJWT vc) throws JOSEException, ParseException {
        LOGGER.info("Transcoding signature");
        Base64URL transcodedSignatureBase64 =
                Base64URL.encode(
                        ECDSA.transcodeSignatureToConcat(
                                vc.getSignature().decode(),
                                ECDSA.getSignatureByteArrayLength(ES256)));

        Base64URL[] jwtParts = vc.getParsedParts();
        return new SignedJWT(jwtParts[0], jwtParts[1], transcodedSignatureBase64);
    }

    private boolean signatureIsDerFormat(SignedJWT signedJWT) throws JOSEException {
        return signedJWT.getSignature().decode().length != ECDSA.getSignatureByteArrayLength(ES256);
    }

    private void validateClaimsSet(
            SignedJWT verifiableCredential,
            CredentialIssuerConfig credentialIssuerConfig,
            String userId) {
        DefaultJWTClaimsVerifier<SimpleSecurityContext> verifier =
                new DefaultJWTClaimsVerifier<>(
                        new JWTClaimsSet.Builder()
                                .issuer(credentialIssuerConfig.getAudienceForClients())
                                .subject(userId)
                                .build(),
                        new HashSet<>(
                                Arrays.asList(
                                        JWTClaimNames.EXPIRATION_TIME,
                                        JWTClaimNames.NOT_BEFORE,
                                        VC_CLAIM_NAME)));

        try {
            verifier.verify(verifiableCredential.getJWTClaimsSet(), null);
        } catch (BadJWTException | ParseException e) {
            LOGGER.error("Verifiable credential claims set not valid: '{}'", e.getMessage());
            throw new CredentialIssuerException(
                    HTTPResponse.SC_SERVER_ERROR,
                    new ErrorObject(
                            OAuth2Error.SERVER_ERROR_CODE,
                            ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL.getMessage()));
        }
    }
}
