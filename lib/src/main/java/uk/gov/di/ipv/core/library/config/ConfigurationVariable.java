package uk.gov.di.ipv.core.library.config;

public enum ConfigurationVariable {
    BACKEND_SESSION_TIMEOUT("self/backendSessionTimeout"),
    BACKEND_SESSION_TTL("self/backendSessionTtl"),
    CLIENT_ISSUER("clients/%s/issuer"),
    COMPONENT_ID("self/componentId"),
    CORE_FRONT_CALLBACK_URL("self/coreFrontCallbackUrl"),
    CORE_VTM_CLAIM("self/coreVtmClaim"),
    JAR_KMS_ENCRYPTION_KEY_ID("self/jarKmsEncryptionKeyId"),
    JWT_TTL_SECONDS("self/jwtTtlSeconds"),
    MAX_ALLOWED_AUTH_CLIENT_TTL("self/maxAllowedAuthClientTtl"),
    DCMAW_SHOULD_SEND_ALL_USERS("self/journey/dcmawShouldSendAllUsers"),
    DCMAW_ALLOWED_USER_IDS("self/journey/dcmawAllowedUserIds"),
    AUTH_CODE_EXPIRY_SECONDS("self/authCodeExpirySeconds"),
    PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY("clients/%s/publicKeyMaterialForCoreToVerify"),
    CI_SCORING_CONFIG("self/ci-scoring-config"),
    CI_SCORING_THRESHOLD("self/ciScoringThreshold"),
    CI_MITIGATION_JOURNEYS_ENABLED("self/journey/ciMitigationsEnabled"),
    VC_TTL("self/vcTtl"),
    VC_VALID_DURATION("self/vcValidDuration");

    private final String path;

    ConfigurationVariable(String path) {

        this.path = path;
    }

    public String getPath() {
        return path;
    }
}
