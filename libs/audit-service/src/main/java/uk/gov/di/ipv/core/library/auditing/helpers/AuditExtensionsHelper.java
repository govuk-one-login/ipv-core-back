package uk.gov.di.ipv.core.library.auditing.helpers;

import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedF2F;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedInheritedIdentity;
import uk.gov.di.ipv.core.library.exceptions.AuditExtensionException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;

import java.text.ParseException;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_BIRTH_DATE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_DRIVING_PERMIT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EXPIRY_DATE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_ID_CARD;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_NAME;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_PASSPORT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_RESIDENCE_PERMIT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_SOCIAL_SECURITY_RECORD;

public class AuditExtensionsHelper {

    private AuditExtensionsHelper() {}

    public static AuditExtensionsVcEvidence getExtensionsForAudit(
            SignedJWT verifiableCredential, Boolean isSuccessful)
            throws ParseException, AuditExtensionException, UnrecognisedVotException {
        var jwtClaimsSet = verifiableCredential.getJWTClaimsSet();
        var vc = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
        var evidence = vc.getAsString(VC_EVIDENCE);
        return new AuditExtensionsVcEvidence(
                jwtClaimsSet.getIssuer(),
                evidence,
                isSuccessful,
                VcHelper.getVcVot(verifiableCredential),
                VcHelper.checkIfDocUKIssuedForCredential(verifiableCredential),
                VcHelper.extractAgeFromCredential(verifiableCredential));
    }

    public static AuditRestrictedF2F getRestrictedAuditDataForF2F(SignedJWT verifiableCredential)
            throws ParseException {
        var jwtClaimsSet = verifiableCredential.getJWTClaimsSet();
        var vc = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
        var credentialSubject = (JSONObject) vc.get(VC_CREDENTIAL_SUBJECT);
        var name = (JSONArray) credentialSubject.get(VC_NAME);

        var passport = (JSONArray) credentialSubject.get(VC_PASSPORT);
        if (passport != null && !passport.isEmpty()) {
            var docExpiryDate = ((JSONObject) passport.get(0)).getAsString(VC_EXPIRY_DATE);
            return new AuditRestrictedF2F(name, docExpiryDate);
        }

        var drivingPermit = (JSONArray) credentialSubject.get(VC_DRIVING_PERMIT);
        if (drivingPermit != null && !drivingPermit.isEmpty()) {
            var docExpiryDate = ((JSONObject) drivingPermit.get(0)).getAsString(VC_EXPIRY_DATE);
            return new AuditRestrictedF2F(name, docExpiryDate);
        }

        var brp = (JSONArray) credentialSubject.get(VC_RESIDENCE_PERMIT);
        if (brp != null && !brp.isEmpty()) {
            var docExpiryDate = ((JSONObject) brp.get(0)).getAsString(VC_EXPIRY_DATE);
            return new AuditRestrictedF2F(name, docExpiryDate);
        }

        var idCard = (JSONArray) credentialSubject.get(VC_ID_CARD);
        if (idCard != null && !idCard.isEmpty()) {
            var docExpiryDate = ((JSONObject) idCard.get(0)).getAsString(VC_EXPIRY_DATE);
            return new AuditRestrictedF2F(name, docExpiryDate);
        }

        return new AuditRestrictedF2F(name);
    }

    public static AuditRestrictedInheritedIdentity getRestrictedAuditDataForInheritedIdentity(
            SignedJWT inheritedIdentityJwt) throws ParseException {
        var vc = (JSONObject) inheritedIdentityJwt.getJWTClaimsSet().getClaim(VC_CLAIM);
        var credentialSubject = (JSONObject) vc.get(VC_CREDENTIAL_SUBJECT);

        return new AuditRestrictedInheritedIdentity(
                (JSONArray) credentialSubject.get(VC_NAME),
                (JSONArray) credentialSubject.get(VC_BIRTH_DATE),
                (JSONArray) credentialSubject.get(VC_SOCIAL_SECURITY_RECORD));
    }
}
