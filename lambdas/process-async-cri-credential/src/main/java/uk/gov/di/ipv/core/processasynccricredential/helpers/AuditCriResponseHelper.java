package uk.gov.di.ipv.core.processasynccricredential.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import uk.gov.di.ipv.core.library.auditing.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.core.processasynccricredential.auditing.AuditRestrictedVcNameParts;

import java.text.ParseException;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;

public class AuditCriResponseHelper {

    private static final String EVIDENCE = "evidence";
    private static final String VC_CREDENTIAL_SUBJECT = "credentialSubject";
    private static final String VC_NAME = "name";
    private static final String VC_NAME_PARTS = "nameParts";

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

    public static AuditRestrictedVcNameParts getVcNamePartsForAudit(SignedJWT verifiableCredential)
            throws ParseException, JsonProcessingException {
        var jwtClaimsSet = verifiableCredential.getJWTClaimsSet();
        var vc = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
        var credentialSubject = (JSONObject) vc.get(VC_CREDENTIAL_SUBJECT);
        var name = (JSONArray) credentialSubject.get(VC_NAME);
        var nameParts = ((JSONObject) name.get(0)).getAsString(VC_NAME_PARTS);
        return new AuditRestrictedVcNameParts(MAPPER.readTree(nameParts));
    }
}
