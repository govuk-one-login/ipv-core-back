package uk.gov.di.ipv.core.library.auditing.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedF2F;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedInheritedIdentity;
import uk.gov.di.ipv.core.library.auditing.restricted.DeviceInformation;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.model.IdentityCheckCredential;
import uk.gov.di.model.IdentityCheckSubject;
import uk.gov.di.model.RiskAssessmentCredential;

import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;

public class AuditExtensionsHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    private AuditExtensionsHelper() {}

    public static AuditExtensionsVcEvidence getExtensionsForAudit(
            VerifiableCredential vc, Boolean isSuccessful) throws UnrecognisedVotException {
        var issuer = vc.getClaimsSet().getIssuer();
        var vot = VcHelper.getVcVot(vc);
        var isUkIssued = VcHelper.checkIfDocUKIssuedForCredential(vc);
        var age = VcHelper.extractAgeFromCredential(vc);

        if (vc.getCredential() instanceof IdentityCheckCredential identityCheckCredential) {
            var identityChecks = identityCheckCredential.getEvidence();

            return new AuditExtensionsVcEvidence(
                    issuer, identityChecks, isSuccessful, vot, isUkIssued, age);
        }

        if (vc.getCredential() instanceof RiskAssessmentCredential riskAssessmentCredential) {
            var riskAssessments = riskAssessmentCredential.getEvidence();

            return new AuditExtensionsVcEvidence(
                    issuer, riskAssessments, isSuccessful, vot, isUkIssued, age);
        }

        return new AuditExtensionsVcEvidence(issuer, null, isSuccessful, vot, isUkIssued, age);
    }

    public static AuditRestrictedF2F getRestrictedAuditDataForF2F(VerifiableCredential vc) {
        if (vc.getCredential().getCredentialSubject()
                instanceof IdentityCheckSubject credentialSubject) {
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
            LOGGER.warn(LogHelper.buildLogMessage("VC not of type IdentityCheckCredential."));
            return new AuditRestrictedF2F(null);
        }
    }

    public static AuditRestrictedInheritedIdentity getRestrictedAuditDataForInheritedIdentity(
            VerifiableCredential vc, String deviceInformation) {
        if (vc.getCredential().getCredentialSubject()
                instanceof IdentityCheckSubject credentialSubject) {
            return new AuditRestrictedInheritedIdentity(
                    credentialSubject.getName(),
                    credentialSubject.getBirthDate(),
                    credentialSubject.getSocialSecurityRecord(),
                    new DeviceInformation(deviceInformation));
        } else {
            LOGGER.warn(LogHelper.buildLogMessage("VC must be of type IdentityCheckCredential."));
            return new AuditRestrictedInheritedIdentity(
                    null, null, null, new DeviceInformation(deviceInformation));
        }
    }
}
