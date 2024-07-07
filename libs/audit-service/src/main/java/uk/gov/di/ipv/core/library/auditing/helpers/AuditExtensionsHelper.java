package uk.gov.di.ipv.core.library.auditing.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedF2F;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedInheritedIdentity;
import uk.gov.di.ipv.core.library.auditing.restricted.DeviceInformation;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.SocialSecurityRecord;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.model.IdentityCheckCredential;

import java.util.List;

import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.CLAIMS_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_BIRTH_DATE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_NAME;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_SOCIAL_SECURITY_RECORD;

public class AuditExtensionsHelper {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    public static final com.fasterxml.jackson.databind.type.CollectionType LIST_NAME_TYPE =
            OBJECT_MAPPER.getTypeFactory().constructCollectionType(List.class, Name.class);
    private static final CollectionType LIST_BIRTH_DATE_TYPE =
            OBJECT_MAPPER.getTypeFactory().constructCollectionType(List.class, BirthDate.class);
    private static final CollectionType LIST_SOCIAL_SECURITY_RECORD_TYPE =
            OBJECT_MAPPER
                    .getTypeFactory()
                    .constructCollectionType(List.class, SocialSecurityRecord.class);

    private AuditExtensionsHelper() {}

    public static AuditExtensionsVcEvidence getExtensionsForAudit(
            VerifiableCredential vc, Boolean isSuccessful) throws UnrecognisedVotException {
        var jwtClaimsSet = vc.getClaimsSet();

        return new AuditExtensionsVcEvidence(
                jwtClaimsSet.getIssuer(),
                OBJECT_MAPPER.valueToTree(jwtClaimsSet.getClaim(VC_CLAIM)).path(VC_EVIDENCE),
                isSuccessful,
                VcHelper.getVcVot(vc),
                VcHelper.checkIfDocUKIssuedForCredential(vc),
                VcHelper.extractAgeFromCredential(vc));
    }

    public static AuditRestrictedF2F getRestrictedAuditDataForF2F(VerifiableCredential vc)
            throws HttpResponseExceptionWithErrorBody {

        if (vc.getCredential() instanceof IdentityCheckCredential identityCheckCredential) {
            var credentialSubject = identityCheckCredential.getCredentialSubject();

            if (credentialSubject == null) {
                LOGGER.error(
                        LogHelper.buildLogMessage(
                                ErrorResponse.CREDENTIAL_SUBJECT_MISSING.getMessage()));
                throw new HttpResponseExceptionWithErrorBody(
                        500, ErrorResponse.CREDENTIAL_SUBJECT_MISSING);
            }

            var name = credentialSubject.getName();

            var passport = credentialSubject.getPassport();
            if (!isNullOrEmpty(passport)) {
                var docExpiryDate = passport.get(0).getExpiryDate();
                return new AuditRestrictedF2F(name, docExpiryDate);
            }

            var drivingPermit = credentialSubject.getDrivingPermit();
            if (!isNullOrEmpty(drivingPermit)) {
                var docExpiryDate = drivingPermit.get(0).getExpiryDate();
                return new AuditRestrictedF2F(name, docExpiryDate);
            }

            var brp = credentialSubject.getResidencePermit();
            if (!isNullOrEmpty(brp)) {
                var docExpiryDate = brp.get(0).getExpiryDate();
                return new AuditRestrictedF2F(name, docExpiryDate);
            }

            var idCard = credentialSubject.getIdCard();
            if (!isNullOrEmpty(idCard)) {
                var docExpiryDate = idCard.get(0).getExpiryDate();
                return new AuditRestrictedF2F(name, docExpiryDate);
            }

            return new AuditRestrictedF2F(name);
        } else {
            LOGGER.error(LogHelper.buildLogMessage("VC must be of type IdentityCheckCredential."));
            throw new HttpResponseExceptionWithErrorBody(
                    500, ErrorResponse.CREDENTIAL_SUBJECT_MISSING);
        }
    }

    public static AuditRestrictedInheritedIdentity getRestrictedAuditDataForInheritedIdentity(
            VerifiableCredential vc, String deviceInformation) throws CredentialParseException {
        var credentialSubject =
                OBJECT_MAPPER
                        .valueToTree(vc.getClaimsSet())
                        .path(CLAIMS_CLAIM)
                        .path(VC_CLAIM)
                        .path(VC_CREDENTIAL_SUBJECT);

        try {
            return new AuditRestrictedInheritedIdentity(
                    OBJECT_MAPPER.treeToValue(credentialSubject.path(VC_NAME), LIST_NAME_TYPE),
                    OBJECT_MAPPER.treeToValue(
                            credentialSubject.path(VC_BIRTH_DATE), LIST_BIRTH_DATE_TYPE),
                    OBJECT_MAPPER.treeToValue(
                            credentialSubject.path(VC_SOCIAL_SECURITY_RECORD),
                            LIST_SOCIAL_SECURITY_RECORD_TYPE),
                    new DeviceInformation(deviceInformation));
        } catch (JsonProcessingException e) {
            throw new CredentialParseException("Unable to parse VC for inherited ID audit data", e);
        }
    }

    private static List<Name> getNameFromCredentialSubject(JsonNode credentialSubject)
            throws CredentialParseException {
        try {
            return OBJECT_MAPPER.treeToValue(credentialSubject.path(VC_NAME), LIST_NAME_TYPE);
        } catch (JsonProcessingException e) {
            throw new CredentialParseException("Unable to get name list from credential subject");
        }
    }
}
