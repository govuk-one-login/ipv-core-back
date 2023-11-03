package uk.gov.di.ipv.core.library.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

public class VerifiableCredentialConstants {
    @ExcludeFromGeneratedCoverageReport
    private VerifiableCredentialConstants() {
        throw new IllegalStateException("Utility class");
    }

    public static final String VC_CONTEXT = "@context";
    public static final String W3_BASE_CONTEXT = "https://www.w3.org/2018/credentials/v1";
    public static final String DI_CONTEXT =
            "https://vocab.london.cloudapps.digital/contexts/identity-v1.jsonld";
    public static final String VC_TYPE = "type";
    public static final String VERIFIABLE_CREDENTIAL_TYPE = "VerifiableCredential";
    public static final String IDENTITY_CHECK_CREDENTIAL_TYPE = "IdentityCheckCredential";
    public static final String VC_CREDENTIAL_SUBJECT = "credentialSubject";
    public static final String VC_EVIDENCE = "evidence";
    public static final String VC_EVIDENCE_VALIDITY = "validityScore";
    public static final String VC_EVIDENCE_STRENGTH = "strengthScore";
    public static final String VC_EVIDENCE_TXN = "txn";
    public static final String VC_CLAIM = "vc";
}
