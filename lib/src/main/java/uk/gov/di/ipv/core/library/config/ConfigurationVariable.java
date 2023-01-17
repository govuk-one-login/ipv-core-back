package uk.gov.di.ipv.core.library.config;

public enum ConfigurationVariable {
    ADDRESS_CRI_ID("/%s/core/self/journey/addressCriId"),
    AUDIENCE_FOR_CLIENTS("/%s/core/self/audienceForClients"),
    BACKEND_SESSION_TIMEOUT("/%s/core/self/backendSessionTimeout"),
    BACKEND_SESSION_TTL("/%s/core/self/backendSessionTtl"),
    CLIENT_ISSUER("/%s/core/clients/%s/issuer"),
    CORE_FRONT_CALLBACK_URL("/%s/core/self/coreFrontCallbackUrl"),
    CORE_VTM_CLAIM("/%s/core/self/coreVtmClaim"),
    FRAUD_CRI_ID("/%s/core/self/journey/fraudCriId"),
    KBV_CRI_ID("/%s/core/self/journey/kbvCriId"),
    DCMAW_CRI_ID("/%s/core/self/journey/dcmawCriId"),
    JAR_KMS_ENCRYPTION_KEY_ID("/%s/core/self/jarKmsEncryptionKeyId"),
    JWT_TTL_SECONDS("/%s/core/self/jwtTtlSeconds"),
    MAX_ALLOWED_AUTH_CLIENT_TTL("/%s/core/self/maxAllowedAuthClientTtl"),
    PASSPORT_CRI_ID("/%s/core/self/journey/passportCriId"),
    DCMAW_ENABLED("/%s/core/self/journey/dcmawEnabled"),
    DCMAW_SHOULD_SEND_ALL_USERS("/%s/core/self/journey/dcmawShouldSendAllUsers"),
    DCMAW_ALLOWED_USER_IDS("/%s/core/self/journey/dcmawAllowedUserIds"),
    AUTH_CODE_EXPIRY_SECONDS("/%s/core/self/authCodeExpirySeconds"),
    PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY("/%s/core/clients/%s/publicKeyMaterialForCoreToVerify"),
    CI_SCORING_CONFIG("/%s/core/self/ci-scoring-config"),
    CI_SCORING_THRESHOLD("/%s/core/self/ciScoringThreshold"),
    CI_MITIGATION_JOURNEYS_ENABLED("/%s/core/self/journey/ciMitigationsEnabled"),
    VC_TTL("/%s/core/self/vcTtl");

    private final String value;

    ConfigurationVariable(String value) {

        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
