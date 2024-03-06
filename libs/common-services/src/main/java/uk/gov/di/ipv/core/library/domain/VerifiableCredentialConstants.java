package uk.gov.di.ipv.core.library.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

public class VerifiableCredentialConstants {
    @ExcludeFromGeneratedCoverageReport
    private VerifiableCredentialConstants() {
        throw new IllegalStateException("Utility class");
    }

    public static final String CRI_STUB_CHECK_EVIDENCE_TYPE = "CriStubCheck";
    public static final String DI_CONTEXT =
            "https://vocab.london.cloudapps.digital/contexts/identity-v1.jsonld";
    public static final String IDENTITY_CHECK_CREDENTIAL_TYPE = "IdentityCheckCredential";
    public static final String IDENTITY_CHECK_EVIDENCE_TYPE = "IdentityCheck";
    public static final String RISK_ASSESSMENT_CREDENTIAL_TYPE = "RiskAssessmentCredential";
    public static final String RISK_ASSESSMENT_EVIDENCE_TYPE = "RiskAssessment";
    public static final String VC_ATTR_VALUE_NAME = "value";
    public static final String VC_BIRTH_DATE = "birthDate";
    public static final String VC_CLAIM = "vc";
    public static final String VC_CONTEXT = "@context";
    public static final String VC_CREDENTIAL_SUBJECT = "credentialSubject";
    public static final String VC_DRIVING_PERMIT = "drivingPermit";
    public static final String VC_DRIVING_LICENCE_ISSUED_BY = "issuedBy";
    public static final String VC_EVIDENCE = "evidence";
    public static final String VC_EVIDENCE_STRENGTH = "strengthScore";
    public static final String VC_EVIDENCE_TXN = "txn";
    public static final String VC_EVIDENCE_VALIDITY = "validityScore";
    public static final String VC_EXPIRY_DATE = "expiryDate";
    public static final String VC_FAMILY_NAME = "FamilyName";
    public static final String VC_GIVEN_NAME = "GivenName";
    public static final String VC_ICAO_ISSUER_CODE = "icaoIssuerCode";
    public static final String VC_ID_CARD = "idCard";
    public static final String VC_NAME = "name";
    public static final String VC_NAME_PARTS = "nameParts";
    public static final String VC_PASSPORT = "passport";
    public static final String VC_RESIDENCE_PERMIT = "residencePermit";
    public static final String VC_SOCIAL_SECURITY_RECORD = "socialSecurityRecord";
    public static final String VC_TYPE = "type";
    public static final String VC_VOT = "vot";
    public static final String VC_VTM = "vtm";
    public static final String VERIFIABLE_CREDENTIAL_TYPE = "VerifiableCredential";
    public static final String W3_BASE_CONTEXT = "https://www.w3.org/2018/credentials/v1";
}
