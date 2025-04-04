package uk.gov.di.ipv.core.library.helpers;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.model.AddressCredential;
import uk.gov.di.model.IdentityAssertionCredential;
import uk.gov.di.model.IdentityCheckCredential;
import uk.gov.di.model.RiskAssessmentCredential;
import uk.gov.di.model.SecurityCheckCredential;
import uk.gov.di.model.VerifiableCredential;
import uk.gov.di.model.VerifiableCredentialType;

import java.text.ParseException;
import java.util.List;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_TYPE;

public class VerifiableCredentialParser {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final ObjectMapper LAX_OBJECT_MAPPER =
            new ObjectMapper()
                    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                    .configure(DeserializationFeature.READ_UNKNOWN_ENUM_VALUES_AS_NULL, true);

    // Known issues with our schema - changes here should be kept in sync with SPOT
    private static final List<String> KNOWN_ADDITIONAL_WARNINGS =
            List.of(
                    "Unrecognized field \"id\" (class uk.gov.di.model.PostalAddress)",
                    "Unrecognized field \"poBoxNumber\" (class uk.gov.di.model.PostalAddress)",
                    "Unrecognized field \"ciReasons\" (class uk.gov.di.model.IdentityCheck)",
                    "Unrecognized field \"deviceId\" (class uk.gov.di.model.IdentityCheckSubject)");

    private VerifiableCredentialParser() {}

    public static VerifiableCredential<?> parseCredential(JWTClaimsSet claimsSet)
            throws CredentialParseException {
        try {
            var vcClaim = claimsSet.getJSONObjectClaim(VC_CLAIM);

            if (vcClaim != null && vcClaim.get(VC_TYPE) instanceof List<?> type) {
                if (type.contains(VerifiableCredentialType.ADDRESS_CREDENTIAL.value())) {
                    return parseCredentialOfType(vcClaim, AddressCredential.class);
                }
                if (type.contains(VerifiableCredentialType.IDENTITY_ASSERTION_CREDENTIAL.value())) {
                    return parseCredentialOfType(vcClaim, IdentityAssertionCredential.class);
                }
                if (type.contains(VerifiableCredentialType.IDENTITY_CHECK_CREDENTIAL.value())) {
                    return parseCredentialOfType(vcClaim, IdentityCheckCredential.class);
                }
                if (type.contains(VerifiableCredentialType.RISK_ASSESSMENT_CREDENTIAL.value())) {
                    return parseCredentialOfType(vcClaim, RiskAssessmentCredential.class);
                }
                if (type.contains(VerifiableCredentialType.SECURITY_CHECK_CREDENTIAL.value())) {
                    return parseCredentialOfType(vcClaim, SecurityCheckCredential.class);
                }
                throw new CredentialParseException("Unknown VC type: " + type);
            }
            throw new CredentialParseException("VC does not contain type field");
        } catch (ParseException | IllegalArgumentException e) {
            throw new CredentialParseException(
                    "Failed parse verifiable credential: " + e.getMessage(), e);
        }
    }

    private static <T extends VerifiableCredential<?>> T parseCredentialOfType(
            Object vcClaim, Class<T> vcType) {
        try {
            return OBJECT_MAPPER.convertValue(vcClaim, vcType);
        } catch (IllegalArgumentException e) {
            // Try again with more relaxed parsing rules
            var vc = LAX_OBJECT_MAPPER.convertValue(vcClaim, vcType);
            if (KNOWN_ADDITIONAL_WARNINGS.stream().noneMatch(m -> e.getMessage().startsWith(m))) {
                LOGGER.warn(
                        LogHelper.buildErrorMessage(
                                "Credential contained unexpected properties: " + e.getMessage(),
                                e));
            }
            return vc;
        }
    }
}
