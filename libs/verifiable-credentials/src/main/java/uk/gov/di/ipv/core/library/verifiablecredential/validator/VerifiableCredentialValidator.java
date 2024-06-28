package uk.gov.di.ipv.core.library.verifiablecredential.validator;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.model.IdentityCheck;
import uk.gov.di.model.IdentityCheckCredential;
import uk.gov.di.model.RiskAssessment;
import uk.gov.di.model.RiskAssessmentCredential;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static com.nimbusds.jose.jwk.KeyType.EC;
import static com.nimbusds.jose.jwk.KeyType.RSA;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;

public class VerifiableCredentialValidator {
    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigService configService;

    public interface IClaimsVerifierFactory {
        DefaultJWTClaimsVerifier<SimpleSecurityContext> createVerifier(
                JWTClaimsSet exactMatchClaims, HashSet<String> requiredClaims);
    }

    private IClaimsVerifierFactory claimsVerifierFactory = DefaultJWTClaimsVerifier::new;

    public VerifiableCredentialValidator(ConfigService configService) {
        this.configService = configService;
    }

    // Constructor for tests where we need to use a fixed time.
    public VerifiableCredentialValidator(
            ConfigService configService, IClaimsVerifierFactory claimsVerifierFactory) {
        this.configService = configService;
        this.claimsVerifierFactory = claimsVerifierFactory;
    }

    public List<VerifiableCredential> parseAndValidate(
            String userId, String criId, List<String> vcs, String signingKey, String componentId)
            throws VerifiableCredentialException {
        var validVcs = new ArrayList<VerifiableCredential>();
        for (String vc : vcs) {
            validVcs.add(parseAndValidate(userId, criId, vc, signingKey, componentId, false));
        }
        return validVcs;
    }

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public VerifiableCredential parseAndValidate(
            String userId,
            String criId,
            String vcString,
            String signingKey,
            String componentId,
            boolean skipSubjectCheck)
            throws VerifiableCredentialException {
        try {
            var vcJwt = SignedJWT.parse(vcString);
            validateSignature(vcJwt, signingKey);
            validateClaimsSet(vcJwt, componentId, userId, skipSubjectCheck);

            var vc = VerifiableCredential.fromValidJwt(userId, criId, vcJwt);

            validateCiCodes(vc);

            LOGGER.info(LogHelper.buildLogMessage("Verifiable Credential validated."));

            return vc;
        } catch (CredentialParseException | ParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error parsing credentials", e));
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        }
    }

    private void validateSignature(SignedJWT vc, String signingKey)
            throws VerifiableCredentialException {
        try {
            var signingKeyType = JWK.parse(signingKey).getKeyType();
            var formattedVc = EC.equals(signingKeyType) ? transcodeSignatureIfDerFormat(vc) : vc;

            var verifier = getVerifier(signingKeyType, signingKey);
            if (!formattedVc.verify(verifier)) {
                LOGGER.error(
                        LogHelper.buildLogMessage("Verifiable credential signature not valid"));
                throw new VerifiableCredentialException(
                        HTTPResponse.SC_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL);
            }
        } catch (ParseException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage("Parse exception when parsing signing key", e));
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL);
        } catch (JOSEException e) {
            LOGGER.error(LogHelper.buildErrorMessage("JOSE exception when verifying signature", e));
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL);
        }
    }

    private JWSVerifier getVerifier(KeyType signingKeyType, String signingKey)
            throws ParseException, JOSEException, VerifiableCredentialException {
        if (EC.equals(signingKeyType)) {
            return new ECDSAVerifier(ECKey.parse(signingKey));
        }

        if (RSA.equals(signingKeyType)) {
            return new RSASSAVerifier(RSAKey.parse(signingKey));
        }

        LOGGER.error(
                LogHelper.buildErrorMessage(
                        "Signing key not valid type", "Signing key is not of type EC or RSA"));
        throw new VerifiableCredentialException(
                HTTPResponse.SC_SERVER_ERROR, ErrorResponse.INVALID_SIGNING_KEY_TYPE);
    }

    private SignedJWT transcodeSignatureIfDerFormat(SignedJWT verifiableCredential)
            throws VerifiableCredentialException {
        try {
            return signatureIsDerFormat(verifiableCredential)
                    ? transcodeSignature(verifiableCredential)
                    : verifiableCredential;
        } catch (JOSEException | ParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error transcoding signature", e));
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL);
        }
    }

    private SignedJWT transcodeSignature(SignedJWT vc) throws JOSEException, ParseException {
        LOGGER.info(LogHelper.buildLogMessage("Transcoding signature"));
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
            String componentId,
            String userId,
            boolean skipSubjectCheck)
            throws VerifiableCredentialException {

        var exactMatchClaimsBuilder = new JWTClaimsSet.Builder().issuer(componentId);
        if (!skipSubjectCheck) {
            exactMatchClaimsBuilder.subject(userId);
        }
        var requiredClaims = new HashSet<>(Arrays.asList(JWTClaimNames.NOT_BEFORE, VC_CLAIM));

        DefaultJWTClaimsVerifier<SimpleSecurityContext> verifier =
                claimsVerifierFactory.createVerifier(
                        exactMatchClaimsBuilder.build(), requiredClaims);

        try {
            verifier.verify(verifiableCredential.getJWTClaimsSet(), null);
        } catch (BadJWTException | ParseException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage("Verifiable credential claims set not valid", e));
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL);
        }
    }

    private void validateCiCodes(VerifiableCredential credential)
            throws VerifiableCredentialException {
        Stream<String> ciCodes;
        if (credential.getCredential() instanceof IdentityCheckCredential icc
                && icc.getEvidence() != null) {
            ciCodes =
                    icc.getEvidence().stream()
                            .map(IdentityCheck::getCi)
                            .filter(Objects::nonNull)
                            .flatMap(Collection::stream);
        } else if (credential.getCredential() instanceof RiskAssessmentCredential rac) {
            ciCodes =
                    rac.getEvidence().stream()
                            .map(RiskAssessment::getCi)
                            .filter(Objects::nonNull)
                            .flatMap(Collection::stream);
        } else {
            return;
        }

        var ciConfig = configService.getContraIndicatorConfigMap();

        if (!ciCodes.allMatch(ciConfig::containsKey)) {
            LOGGER.error(
                    LogHelper.buildLogMessage(
                            "Verifiable credential contains unrecognised CI codes"));
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL);
        }
    }
}
