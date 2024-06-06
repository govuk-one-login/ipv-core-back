package uk.gov.di.ipv.core.library.verifiablecredential.validator;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.ECKey;
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
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.VerifiableCredentialParser;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;

public class VerifiableCredentialValidator {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final CollectionType CREDENTIAL_EVIDENCE_ITEM_LIST_TYPE =
            OBJECT_MAPPER
                    .getTypeFactory()
                    .constructCollectionType(List.class, CredentialEvidenceItem.class);
    private static final String VC_CLAIM_NAME = "vc";
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
            String userId,
            String criId,
            List<String> vcs,
            String vcType,
            ECKey signingKey,
            String componentId)
            throws VerifiableCredentialException {
        var validVcs = new ArrayList<VerifiableCredential>();
        for (String vc : vcs) {
            validVcs.add(
                    parseAndValidate(userId, criId, vc, vcType, signingKey, componentId, false));
        }
        return validVcs;
    }

    public VerifiableCredential parseAndValidate(
            String userId,
            String criId,
            String vcString,
            String vcType,
            ECKey signingKey,
            String componentId,
            boolean skipSubjectCheck)
            throws VerifiableCredentialException {
        try {
            var vcJwt = SignedJWT.parse(vcString);
            validateSignature(vcJwt, signingKey);
            validateClaimsSet(vcJwt, componentId, userId, skipSubjectCheck);

            var vc = VerifiableCredential.fromValidJwt(userId, criId, vcJwt);
            if (configService.enabled(CoreFeatureFlag.PARSE_VC_CLASSES)) {
                // This only checks newly received VCs (behind a feature flag)
                // but once comfortable we will move this into the VerifiableCredential class itself
                try {
                    VerifiableCredentialParser.parseCredential(vc.getClaimsSet());
                } catch (CredentialParseException e) {
                    // For now, we just log a warning here that we can fix
                    // In future this should return a CredentialParseException instead
                    LOGGER.warn(
                            LogHelper.buildErrorMessage(
                                    "Failed to parse verifiable credential", e));
                }
            }
            if (VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE.equals(vcType)) {
                validateCiCodes(vc);
            }
            LOGGER.info(LogHelper.buildLogMessage("Verifiable Credential validated."));

            return vc;
        } catch (CredentialParseException | ParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error parsing credentials", e));
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        }
    }

    private void validateSignature(SignedJWT verifiableCredential, ECKey signingKey)
            throws VerifiableCredentialException {
        SignedJWT concatSignatureVerifiableCredential;
        try {
            concatSignatureVerifiableCredential =
                    signatureIsDerFormat(verifiableCredential)
                            ? transcodeSignature(verifiableCredential)
                            : verifiableCredential;
        } catch (JOSEException | ParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error transcoding signature", e));
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL);
        }

        try {
            ECDSAVerifier verifier = new ECDSAVerifier(signingKey);
            if (!concatSignatureVerifiableCredential.verify(verifier)) {
                LOGGER.error(
                        LogHelper.buildLogMessage("Verifiable credential signature not valid"));
                throw new VerifiableCredentialException(
                        HTTPResponse.SC_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL);
            }
        } catch (JOSEException e) {
            LOGGER.error(LogHelper.buildErrorMessage("JOSE exception when verifying signature", e));
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
        var requiredClaims = new HashSet<>(Arrays.asList(JWTClaimNames.NOT_BEFORE, VC_CLAIM_NAME));

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

    private void validateCiCodes(VerifiableCredential vc) throws VerifiableCredentialException {
        try {
            var evidenceArray =
                    OBJECT_MAPPER
                            .valueToTree(vc.getClaimsSet().getClaim(VC_CLAIM))
                            .path(VC_EVIDENCE);
            if (evidenceArray.isArray()) {
                List<CredentialEvidenceItem> credentialEvidenceList =
                        OBJECT_MAPPER.treeToValue(
                                evidenceArray, CREDENTIAL_EVIDENCE_ITEM_LIST_TYPE);
                boolean anyUnrecognisedCiCodes = false;
                for (CredentialEvidenceItem evidenceItem : credentialEvidenceList) {
                    List<String> cis = evidenceItem.getCi();
                    if (cis != null) {
                        anyUnrecognisedCiCodes =
                                cis.stream()
                                        .anyMatch(
                                                ciCode ->
                                                        !configService
                                                                .getContraIndicatorConfigMap()
                                                                .containsKey(ciCode));
                        if (anyUnrecognisedCiCodes) {
                            break;
                        }
                    }
                }

                if (anyUnrecognisedCiCodes) {
                    LOGGER.error(
                            LogHelper.buildLogMessage(
                                    "Verifiable credential contains unrecognised CI codes"));
                    throw new VerifiableCredentialException(
                            HTTPResponse.SC_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL);
                }
            }
        } catch (VerifiableCredentialException | JsonProcessingException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Failed to parse verifiable credential claims set", e));
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL);
        }
    }
}
