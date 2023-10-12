package uk.gov.di.ipv.core.processasynccricredential.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.core.processasynccricredential.auditing.AuditRestrictedVc;

import java.text.ParseException;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;

public class AuditCriResponseHelper {

    private static final String EVIDENCE = "evidence";
    private static final String VC_CREDENTIAL_SUBJECT = "credentialSubject";
    private static final String VC_NAME = "name";
    private static final String VC_PASSPORT = "passport";
    private static final String VC_EXPIRY_DATE = "expiryDate";
    private static final String VC_DRIVING_PERMIT = "drivingPermit";

    private AuditCriResponseHelper() {}

    public static AuditExtensionsVcEvidence getExtensionsForAudit(
            SignedJWT verifiableCredential, boolean isSuccessful)
            throws ParseException, JsonProcessingException {
        var jwtClaimsSet = verifiableCredential.getJWTClaimsSet();
        var vc = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
        var evidence = vc.getAsString(EVIDENCE);
        return new AuditExtensionsVcEvidence(jwtClaimsSet.getIssuer(), evidence, isSuccessful);
    }

    public static AuditRestrictedVc getRestrictedDataForAuditEvent(SignedJWT verifiableCredential)
            throws ParseException {
        var jwtClaimsSet = verifiableCredential.getJWTClaimsSet();
        var vc = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
        var credentialSubject = (JSONObject) vc.get(VC_CREDENTIAL_SUBJECT);
        var name = (JSONArray) credentialSubject.get(VC_NAME);

        var passport = (JSONArray) credentialSubject.get(VC_PASSPORT);
        if (passport != null && !passport.isEmpty()) {
            var docExpiryDate = ((JSONObject) passport.get(0)).getAsString(VC_EXPIRY_DATE);
            return new AuditRestrictedVc(name, docExpiryDate);
        }

        var drivingPermit = (JSONArray) credentialSubject.get(VC_DRIVING_PERMIT);
        if (drivingPermit != null && !drivingPermit.isEmpty()) {
            var docExpiryDate = ((JSONObject) drivingPermit.get(0)).getAsString(VC_EXPIRY_DATE);
            return new AuditRestrictedVc(name, docExpiryDate);
        }

        return new AuditRestrictedVc(name);
    }
}
