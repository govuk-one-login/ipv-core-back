package uk.gov.di.ipv.core.library.verifiablecredential.validator;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.logging.log4j.Level;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CriConfig;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;

public class VerifiableCredentialJwtValidator {
    private static final String VC_CLAIM_NAME = "vc";
    private static final Gson gson = new Gson();
    private final ConfigService configService;

    public interface IClaimsVerifierFactory {
        DefaultJWTClaimsVerifier<SimpleSecurityContext> createVerifier(
                JWTClaimsSet exactMatchClaims, HashSet<String> requiredClaims);
    }

    private IClaimsVerifierFactory claimsVerifierFactory = DefaultJWTClaimsVerifier::new;

    public VerifiableCredentialJwtValidator(ConfigService configService) {
        this.configService = configService;
    }

    // Constructor for tests where we need to use a fixed time.
    public VerifiableCredentialJwtValidator(
            ConfigService configService, IClaimsVerifierFactory claimsVerifierFactory) {
        this.configService = configService;
        this.claimsVerifierFactory = claimsVerifierFactory;
    }

    public void validate(
            SignedJWT verifiableCredential, CriConfig credentialIssuerConfig, String userId)
            throws VerifiableCredentialException {
        LogHelper.logMessage(Level.INFO, "Validating Verifiable Credential.");
        ECKey signingKey;
        try {
            signingKey = credentialIssuerConfig.getSigningKey();
        } catch (ParseException e) {
            LogHelper.logErrorMessage("Error parsing credential issuer public JWK", e.getMessage());
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_PARSE_JWK);
        }
        validate(verifiableCredential, signingKey, credentialIssuerConfig.getComponentId(), userId);
    }

    public void validate(
            SignedJWT verifiableCredential, ECKey signingKey, String componentId, String userId)
            throws VerifiableCredentialException {
        validateSignatureAndClaims(verifiableCredential, signingKey, componentId, userId);
        validateCiCodes(verifiableCredential);
        LogHelper.logMessage(Level.INFO, "Verifiable Credential validated.");
    }

    public void validateSignatureAndClaims(
            SignedJWT verifiableCredential, ECKey signingKey, String componentId, String userId)
            throws VerifiableCredentialException {
        validateSignature(verifiableCredential, signingKey);
        validateClaimsSet(verifiableCredential, componentId, userId);
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
            LogHelper.logErrorMessage("Error transcoding signature.", e.getMessage());
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL);
        }

        try {
            ECDSAVerifier verifier = new ECDSAVerifier(signingKey);
            if (!concatSignatureVerifiableCredential.verify(verifier)) {
                LogHelper.logErrorMessage("Verifiable credential signature not valid");
                throw new VerifiableCredentialException(
                        HTTPResponse.SC_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL);
            }
        } catch (JOSEException e) {
            LogHelper.logErrorMessage("JOSE exception when verifying signature.", e.getMessage());
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL);
        }
    }

    private SignedJWT transcodeSignature(SignedJWT vc) throws JOSEException, ParseException {
        LogHelper.logMessage(Level.INFO, "Transcoding signature.");
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
            SignedJWT verifiableCredential, String componentId, String userId)
            throws VerifiableCredentialException {

        var exactMatchClaims =
                new JWTClaimsSet.Builder().issuer(componentId).subject(userId).build();
        var requiredClaims = new HashSet<>(Arrays.asList(JWTClaimNames.NOT_BEFORE, VC_CLAIM_NAME));

        DefaultJWTClaimsVerifier<SimpleSecurityContext> verifier =
                claimsVerifierFactory.createVerifier(exactMatchClaims, requiredClaims);

        try {
            verifier.verify(verifiableCredential.getJWTClaimsSet(), null);
        } catch (BadJWTException | ParseException e) {
            LogHelper.logErrorMessage("Verifiable credential claims set not valid", e.getMessage());
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL);
        }
    }

    private void validateCiCodes(SignedJWT verifiableCredential)
            throws VerifiableCredentialException {
        Map<String, ContraIndicatorConfig> contraIndicatorConfigMap =
                configService.getContraIndicatorConfigMap();

        try {
            JSONObject vcClaim =
                    (JSONObject) verifiableCredential.getJWTClaimsSet().getClaim(VC_CLAIM);
            JSONArray evidenceArray = (JSONArray) vcClaim.get(VC_EVIDENCE);
            if (evidenceArray != null) {
                List<CredentialEvidenceItem> credentialEvidenceList =
                        gson.fromJson(
                                evidenceArray.toJSONString(),
                                new TypeToken<List<CredentialEvidenceItem>>() {}.getType());

                boolean anyUnrecognisedCiCodes = false;
                for (CredentialEvidenceItem evidenceItem : credentialEvidenceList) {
                    List<String> cis = evidenceItem.getCi();
                    if (cis != null) {
                        anyUnrecognisedCiCodes =
                                cis.stream()
                                        .anyMatch(
                                                ciCode ->
                                                        !contraIndicatorConfigMap.containsKey(
                                                                ciCode));
                        if (anyUnrecognisedCiCodes) {
                            break;
                        }
                    }
                }

                if (anyUnrecognisedCiCodes) {
                    LogHelper.logErrorMessage(
                            "Verifiable credential contains unrecognised CI codes");
                    throw new VerifiableCredentialException(
                            HTTPResponse.SC_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL);
                }
            }
        } catch (ParseException | VerifiableCredentialException e) {
            LogHelper.logErrorMessage(
                    "Failed to parse verifiable credential claims set", e.getMessage());
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL);
        }
    }
}
