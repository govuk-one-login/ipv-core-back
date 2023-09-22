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
    AUTH_CODE_EXPIRY_SECONDS("self/authCodeExpirySeconds"),
    PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY("clients/%s/publicKeyMaterialForCoreToVerify"),
    CLIENT_VALID_REDIRECT_URLS("clients/%s/validRedirectUrls"),
    CI_SCORING_CONFIG("self/ci-scoring-config"),
    CI_SCORING_THRESHOLD("self/checkCiScoreThreshold"),
    VC_TTL("self/vcTtl"),
    CREDENTIAL_ISSUERS("credentialIssuers"),
    FEATURE_FLAGS("featureFlags/%s"),
    CRI_RESPONSE_TTL("self/criResponseTtl"),
    JOURNEY_TYPE("self/journey/type"),
    CIMIT_SIGNING_KEY("cimit/signingKey"),
    CIMIT_COMPONENT_ID("cimit/componentId"),
    CIMIT_CONFIG("cimit/config");

    private final String path;

    ConfigurationVariable(String path) {

        this.path = path;
    }

    public String getPath() {
        return path;
    }
}
