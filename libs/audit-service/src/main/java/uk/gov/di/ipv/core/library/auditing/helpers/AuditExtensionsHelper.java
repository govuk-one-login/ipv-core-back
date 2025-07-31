package uk.gov.di.ipv.core.library.auditing.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedAsync;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.model.IdentityCheckCredential;
import uk.gov.di.model.IdentityCheckSubject;
import uk.gov.di.model.RiskAssessmentCredential;

import java.util.List;

import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;

public class AuditExtensionsHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    private AuditExtensionsHelper() {}

    public static AuditExtensionsVcEvidence getExtensionsForAudit(
            VerifiableCredential vc, Boolean isSuccessful) throws UnrecognisedVotException {
        return getExtensionsForAudit(vc, isSuccessful, null);
    }

    public static AuditExtensionsVcEvidence getExtensionsForAuditWithCriId(
            VerifiableCredential vc, Boolean isSuccessful) throws UnrecognisedVotException {
        return getExtensionsForAudit(vc, isSuccessful, vc.getCri().getId());
    }

    private static AuditExtensionsVcEvidence getExtensionsForAudit(
            VerifiableCredential vc, Boolean isSuccessful, String cridId)
            throws UnrecognisedVotException {
        var issuer = vc.getClaimsSet().getIssuer();
        var vot = VcHelper.getVcVot(vc);
        var isUkIssued = VcHelper.checkIfDocUKIssuedForCredential(vc);
        var age = VcHelper.extractAgeFromCredential(vc);
        List<?> evidence = null;
        if (vc.getCredential() instanceof IdentityCheckCredential identityCheckCredential) {
            evidence = identityCheckCredential.getEvidence();
        }
        if (vc.getCredential() instanceof RiskAssessmentCredential riskAssessmentCredential) {
            evidence = riskAssessmentCredential.getEvidence();
        }
        return new AuditExtensionsVcEvidence(
                issuer, evidence, isSuccessful, vot, isUkIssued, age, cridId);
    }

    public static AuditRestrictedAsync getRestrictedAuditDataForAsync(VerifiableCredential vc) {
        if (vc.getCredential().getCredentialSubject()
                instanceof IdentityCheckSubject credentialSubject) {
            var name = credentialSubject.getName();

            var passport = credentialSubject.getPassport();
            if (!isNullOrEmpty(passport)) {
                var docExpiryDate = passport.get(0).getExpiryDate();
                return new AuditRestrictedAsync(name, docExpiryDate);
            }

            var drivingPermit = credentialSubject.getDrivingPermit();
            if (!isNullOrEmpty(drivingPermit)) {
                var docExpiryDate = drivingPermit.get(0).getExpiryDate();
                return new AuditRestrictedAsync(name, docExpiryDate);
            }

            var brp = credentialSubject.getResidencePermit();
            if (!isNullOrEmpty(brp)) {
                var docExpiryDate = brp.get(0).getExpiryDate();
                return new AuditRestrictedAsync(name, docExpiryDate);
            }

            var idCard = credentialSubject.getIdCard();
            if (!isNullOrEmpty(idCard)) {
                var docExpiryDate = idCard.get(0).getExpiryDate();
                return new AuditRestrictedAsync(name, docExpiryDate);
            }

            return new AuditRestrictedAsync(name);
        } else {
            LOGGER.warn(LogHelper.buildLogMessage("VC not of type IdentityCheckCredential."));
            return new AuditRestrictedAsync(null);
        }
    }
}
