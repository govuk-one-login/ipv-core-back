package uk.gov.di.ipv.core.library.auditing.helpers;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedF2F;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedInheritedIdentity;
import uk.gov.di.ipv.core.library.auditing.restricted.DeviceInformation;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.model.IdentityCheckCredential;
import uk.gov.di.model.IdentityCheckSubject;

import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;

public class AuditExtensionsHelper {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

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
            var credentialSubject = getCredentialSubjectOrThrow(identityCheckCredential);

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
            VerifiableCredential vc, String deviceInformation)
            throws CredentialParseException, HttpResponseExceptionWithErrorBody {
        if (vc.getCredential() instanceof IdentityCheckCredential identityCheckCredential) {
            var credentialSubject = getCredentialSubjectOrThrow(identityCheckCredential);

            return new AuditRestrictedInheritedIdentity(
                    credentialSubject.getName(),
                    credentialSubject.getBirthDate(),
                    credentialSubject.getSocialSecurityRecord(),
                    new DeviceInformation(deviceInformation));
        } else {
            LOGGER.error(LogHelper.buildLogMessage("VC must be of type IdentityCheckCredential."));
            throw new HttpResponseExceptionWithErrorBody(
                    500, ErrorResponse.CREDENTIAL_SUBJECT_MISSING);
        }
    }

    private static IdentityCheckSubject getCredentialSubjectOrThrow(
            IdentityCheckCredential credential) throws HttpResponseExceptionWithErrorBody {
        var credentialSubject = credential.getCredentialSubject();

        if (credentialSubject == null) {
            LOGGER.error(
                    LogHelper.buildLogMessage(
                            ErrorResponse.CREDENTIAL_SUBJECT_MISSING.getMessage()));
            throw new HttpResponseExceptionWithErrorBody(
                    500, ErrorResponse.CREDENTIAL_SUBJECT_MISSING);
        }

        return credentialSubject;
    }
}
