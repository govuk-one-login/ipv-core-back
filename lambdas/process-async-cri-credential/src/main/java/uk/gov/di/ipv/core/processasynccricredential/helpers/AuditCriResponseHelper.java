package uk.gov.di.ipv.core.processasynccricredential.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
    private static final String VC_NAME_PARTS = "nameParts";
    private static final String VC_PASSPORT = "passport";
    private static final String VC_EXPIRY_DATE = "expiryDate";

    private static final String VC_DRIVING_PERMIT = "drivingPermit";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private AuditCriResponseHelper() {}

    public static AuditExtensionsVcEvidence getExtensionsForAudit(
            SignedJWT verifiableCredential, boolean isSuccessful)
            throws ParseException, JsonProcessingException {
        var jwtClaimsSet = verifiableCredential.getJWTClaimsSet();
        var vc = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
        var evidence = vc.getAsString(EVIDENCE);
        return new AuditExtensionsVcEvidence(jwtClaimsSet.getIssuer(), evidence, isSuccessful);
    }

    public static AuditRestrictedVc getVcNamePartsForAudit(SignedJWT verifiableCredential)
            throws ParseException, JsonProcessingException {
        var jwtClaimsSet = verifiableCredential.getJWTClaimsSet();
        var vc = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
        var credentialSubject = (JSONObject) vc.get(VC_CREDENTIAL_SUBJECT);
        var name = (JSONArray) credentialSubject.get(VC_NAME);
        var nameParts = ((JSONObject) name.get(0)).getAsString(VC_NAME_PARTS);

        var passport = (JSONArray) credentialSubject.get(VC_PASSPORT);
        if (passport.size() != 0) {
            var docExpiryDate = ((JSONObject) passport.get(0)).getAsString(VC_EXPIRY_DATE);
            return new AuditRestrictedVc(MAPPER.readTree(nameParts), docExpiryDate);
        }
        var drivingPermit = (JSONArray) credentialSubject.get(VC_DRIVING_PERMIT);
        var docExpiryDate = ((JSONObject) drivingPermit.get(0)).getAsString(VC_EXPIRY_DATE);
        return new AuditRestrictedVc(MAPPER.readTree(nameParts), docExpiryDate);
    }
}
