package uk.gov.di.ipv.core.library.domain;

public class VocabConstants {
    private VocabConstants() {
        throw new IllegalStateException("Utility class");
    }

    public static final String ADDRESS_CLAIM_NAME = "https://vocab.account.gov.uk/v1/address";
    public static final String CORE_IDENTITY_JWT_CLAIM_NAME =
            "https://vocab.account.gov.uk/v1/coreIdentityJWT";
    public static final String DRIVING_PERMIT_CLAIM_NAME =
            "https://vocab.account.gov.uk/v1/drivingPermit";
    public static final String IDENTITY_CLAIM_NAME = "https://vocab.account.gov.uk/v1/coreIdentity";
    public static final String INHERITED_IDENTITY_JWT_CLAIM_NAME =
            "https://vocab.account.gov.uk/v1/inheritedIdentityJWT";
    public static final String NINO_CLAIM_NAME =
            "https://vocab.account.gov.uk/v1/socialSecurityRecord";
    public static final String PASSPORT_CLAIM_NAME = "https://vocab.account.gov.uk/v1/passport";
    public static final String RETURN_CODE_NAME = "https://vocab.account.gov.uk/v1/returnCode";
    public static final String VCS_CLAIM_NAME = "https://vocab.account.gov.uk/v1/credentialJWT";
}
