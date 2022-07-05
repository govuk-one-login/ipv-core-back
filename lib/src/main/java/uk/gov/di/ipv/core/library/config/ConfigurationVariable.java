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
    JAR_KMS_ENCRYPTION_KEY_ID("/%s/core/self/jarKmsEncryptionKeyId"),
    JWT_TTL_SECONDS("/%s/core/self/jwtTtlSeconds"),
    MAX_ALLOWED_AUTH_CLIENT_TTL("/%s/core/self/maxAllowedAuthClientTtl"),
    PASSPORT_CRI_ID("/%s/core/self/journey/passportCriId"),
    PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY("/%s/core/clients/%s/publicKeyMaterialForCoreToVerify");

    private final String value;

    ConfigurationVariable(String value) {

        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
