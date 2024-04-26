package uk.gov.di.ipv.core.library.helpers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
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

import java.util.List;

public class VerifiableCredentialParser {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Logger LOGGER = LogManager.getLogger();

    private VerifiableCredentialParser() {}

    public static VerifiableCredential parseCredential(SignedJWT jwt) {
        try {
            var vcClaim = jwt.getJWTClaimsSet().getJSONObjectClaim("vc");
            var vcType = vcClaim.get("type");

            if (vcType instanceof List<?> type) {
                if (type.contains(VerifiableCredentialType.ADDRESS_CREDENTIAL.value())) {
                    return OBJECT_MAPPER.convertValue(vcClaim, AddressCredential.class);
                }
                if (type.contains(VerifiableCredentialType.IDENTITY_ASSERTION_CREDENTIAL.value())) {
                    return OBJECT_MAPPER.convertValue(vcClaim, IdentityAssertionCredential.class);
                }
                if (type.contains(VerifiableCredentialType.IDENTITY_CHECK_CREDENTIAL.value())) {
                    return OBJECT_MAPPER.convertValue(vcClaim, IdentityCheckCredential.class);
                }
                if (type.contains(VerifiableCredentialType.RISK_ASSESSMENT_CREDENTIAL.value())) {
                    return OBJECT_MAPPER.convertValue(vcClaim, RiskAssessmentCredential.class);
                }
                if (type.contains(VerifiableCredentialType.SECURITY_CHECK_CREDENTIAL.value())) {
                    return OBJECT_MAPPER.convertValue(vcClaim, SecurityCheckCredential.class);
                }
                throw new CredentialParseException("Unknown VC type: " + type);
            }
            throw new CredentialParseException("VC does not contain type field");
        } catch (Exception e) {
            // For now, we just log a warning here that we can fix
            // In future this should return a CredentialParseException instead
            LOGGER.warn(LogHelper.buildErrorMessage("Failed to parse verifiable credential", e));
            return null;
        }
    }
}
