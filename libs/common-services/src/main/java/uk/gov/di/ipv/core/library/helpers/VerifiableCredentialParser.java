package uk.gov.di.ipv.core.library.helpers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
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

public class VerifiableCredentialParser {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private VerifiableCredentialParser() {}

    public static VerifiableCredential parseCredential(JWTClaimsSet claimsSet)
            throws CredentialParseException {
        try {
            var vcClaim = claimsSet.getJSONObjectClaim("vc");

            if (vcClaim != null && vcClaim.get("type") instanceof List<?> type) {
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
        } catch (ParseException | IllegalArgumentException e) {
            throw new CredentialParseException("Failed parse verifiable credential", e);
        }
    }
}
